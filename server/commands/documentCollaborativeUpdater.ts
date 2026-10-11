import isEqual from "fast-deep-equal";
import { uniq } from "es-toolkit/compat";
import { Node } from "prosemirror-model";
import { yDocToProsemirrorJSON } from "y-prosemirror";
import * as Y from "yjs";
import type { ProsemirrorData } from "@shared/types";
import { schema } from "@server/editor";
import Logger from "@server/logging/Logger";
import { Document, Event } from "@server/models";
import { sequelize } from "@server/storage/database";
import { AuthenticationType } from "@server/types";
import semver from "semver";

type Props = {
  /** The document ID to update. */
  documentId: string;
  /** Current collaobrative state. */
  ydoc: Y.Doc;
  /** The user IDs that have modified the document since it was last persisted. */
  sessionCollaboratorIds: string[];
  /** Whether the last connection to the document left. */
  isLastConnection: boolean;
  /** The client version, if available. */
  clientVersion: string | null;
};

/**
 * Window after a PG write during which an empty collaborative save is treated
 * as a stale reconnect rather than a deliberate clear. Steady-state clears of
 * older documents persist exactly as before.
 */
const EMPTY_OVER_FRESH_WINDOW_MS = 5 * 60 * 1000;

function isEffectivelyEmpty(data: ProsemirrorData): boolean {
  try {
    return Node.fromJSON(schema, data).textContent.trim().length === 0;
  } catch {
    return false;
  }
}

function isPassingEmptyStateOverFreshContent(
  pgUpdatedAt: Date,
  memoryContent: ProsemirrorData,
  pgContent: ProsemirrorData | null
): boolean {
  if (!pgContent) {
    return false;
  }
  if (
    Date.now() - new Date(pgUpdatedAt).getTime() >
    EMPTY_OVER_FRESH_WINDOW_MS
  ) {
    return false;
  }
  if (!isEffectivelyEmpty(memoryContent)) {
    return false;
  }
  return !isEffectivelyEmpty(pgContent);
}

export default async function documentCollaborativeUpdater({
  documentId,
  ydoc,
  sessionCollaboratorIds,
  isLastConnection,
  clientVersion,
}: Props) {
  return sequelize.transaction(async (transaction) => {
    await sequelize.query(`SET LOCAL lock_timeout = '15s';`, {
      transaction,
    });

    const document = await Document.unscoped()
      .scope("withoutState")
      .findOne({
        where: {
          id: documentId,
        },
        transaction,
        lock: {
          of: Document,
          level: transaction.LOCK.UPDATE,
        },
        rejectOnEmpty: true,
        paranoid: false,
      });

    const state = Y.encodeStateAsUpdate(ydoc);

    // Round-trip through the schema so the stored JSON is canonical. The raw
    // y-prosemirror output includes empty `attrs: {}` on every mark, and outputs
    // properties in a different order - resulting in spurious "edits"
    const content = Node.fromJSON(
      schema,
      yDocToProsemirrorJSON(ydoc, "default")
    ).toJSON() as ProsemirrorData;
    const isUnchanged = isEqual(document.content, content);
    const isDeleted = !!document.deletedAt;
    const lastModifiedById = isDeleted
      ? document.lastModifiedById
      : (sessionCollaboratorIds[sessionCollaboratorIds.length - 1] ??
        document.lastModifiedById);

    if (isUnchanged) {
      return;
    }

    if (
      !isDeleted &&
      isPassingEmptyStateOverFreshContent(document.updatedAt, content, document.content)
    ) {
      Logger.warn(
        `Refusing to persist empty collaborative state over fresh content for ${documentId} (pg updated ${document.updatedAt.toISOString()})`
      );
      return;
    }

    Logger.info(
      "multiplayer",
      `Persisting ${documentId}, attributed to ${lastModifiedById}`
    );

    // extract collaborators from doc user data
    const pud = new Y.PermanentUserData(ydoc);
    const pudIds = Array.from(pud.clients.values());
    const collaboratorIds = uniq([
      ...(document.collaboratorIds ?? []),
      ...sessionCollaboratorIds,
      ...pudIds,
    ]);

    // Either the client or server version could be null, or they could both be
    // set. In that case we want to use the greater (newer) version.
    const editorVersion =
      document.editorVersion && clientVersion
        ? semver.gt(clientVersion, document.editorVersion)
          ? clientVersion
          : document.editorVersion
        : clientVersion
          ? clientVersion
          : document.editorVersion;

    await document.update(
      {
        content,
        state: Buffer.from(state),
        lastModifiedById,
        collaboratorIds,
        editorVersion,
      },
      {
        transaction,
        // Hooks MUST NOT be called or the AfterUpdate hook in Document model may
        // result in infinite processing.
        hooks: false,
      }
    );

    await Event.schedule({
      name: "documents.update",
      documentId: document.id,
      collectionId: document.collectionId,
      teamId: document.teamId,
      actorId: lastModifiedById,
      authType: AuthenticationType.APP,
      data: {
        multiplayer: true,
        title: document.title,
        done: isLastConnection,
      },
    });
  });
}
