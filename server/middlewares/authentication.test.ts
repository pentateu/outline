import type { DefaultState } from "koa";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import type { CryptoKey } from "jose";
import { http, HttpResponse } from "msw";
import { errToString } from "@shared/utils/error";
import { randomString } from "@shared/random";
import { Scope } from "@shared/types";
import {
  buildUser,
  buildTeam,
  buildAdmin,
  buildApiKey,
  buildOAuthAuthentication,
} from "@server/test/factories";
import { server } from "@server/test/msw";
import type { AppContext } from "@server/types";
import { AuthenticationType } from "@server/types";
import oidcEnv from "plugins/oidc/server/env";
import auth from "./authentication";

describe("Authentication middleware", () => {
  const buildCookieContext = (token: string) => {
    const state = {} as DefaultState;
    const ctx = {
      request: { get: () => "" },
      cookies: { get: () => token },
      state,
      cache: {},
    } as unknown as AppContext;

    return { ctx, state };
  };

  describe("with session JWT", () => {
    it("should authenticate with correct session token", async () => {
      const state = {} as DefaultState;
      const user = await buildUser();
      const authMiddleware = auth();
      await authMiddleware(
        {
          // @ts-expect-error mock request
          request: {
            get: vi.fn(() => `Bearer ${user.getSessionToken()}`),
          },
          state,
          cache: {},
        },
        vi.fn()
      );
      expect(state.auth.user.id).toEqual(user.id);
    });

    it("should return error with invalid session token", async () => {
      const state = {} as DefaultState;
      const user = await buildUser();
      const authMiddleware = auth();

      try {
        await authMiddleware(
          {
            // @ts-expect-error mock request
            request: {
              get: vi.fn(() => `Bearer ${user.getSessionToken()}error`),
            },
            state,
            cache: {},
          },
          vi.fn()
        );
      } catch (e) {
        expect(errToString(e)).toBe("Invalid token");
      }
    });

    it("should return error if AuthenticationType mismatches", async () => {
      const state = {} as DefaultState;
      const user = await buildUser();
      const authMiddleware = auth({
        type: AuthenticationType.API,
      });

      try {
        await authMiddleware(
          {
            // @ts-expect-error mock request
            request: {
              get: vi.fn(() => `Bearer ${user.getSessionToken()}`),
            },
            state,
            cache: {},
          },
          vi.fn()
        );
      } catch (e) {
        expect(errToString(e)).toBe("Invalid authentication type");
      }
    });
  });

  describe("with API key", () => {
    it("should authenticate user with valid API key", async () => {
      const state = {} as DefaultState;
      const user = await buildUser();
      const authMiddleware = auth();
      const key = await buildApiKey({ userId: user.id });
      await authMiddleware(
        {
          // @ts-expect-error mock request
          request: {
            get: vi.fn(() => `Bearer ${key.value}`),
          },
          state,
          cache: {},
        },
        vi.fn()
      );
      expect(state.auth.user.id).toEqual(user.id);
    });
    it("should authenticate with global read scope on read endpoints", async () => {
      const state = {} as DefaultState;
      const user = await buildUser();
      const authMiddleware = auth();
      const key = await buildApiKey({
        userId: user.id,
        scope: [Scope.Read],
      });

      await authMiddleware(
        {
          originalUrl: "/api/auth.info",
          // @ts-expect-error mock request
          request: {
            url: "/auth.info",
            get: vi.fn(() => `Bearer ${key.value}`),
          },
          state,
          cache: {},
        },
        vi.fn()
      );
      expect(state.auth.user.id).toEqual(user.id);
    });

    it("should return 403 authorization error when scope does not match", async () => {
      const state = {} as DefaultState;
      const user = await buildUser();
      const authMiddleware = auth();
      const key = await buildApiKey({
        userId: user.id,
        scope: [Scope.Read],
      });

      try {
        await authMiddleware(
          {
            originalUrl: "/api/documents.create",
            // @ts-expect-error mock request
            request: {
              url: "/documents.create",
              get: vi.fn(() => `Bearer ${key.value}`),
            },
            state,
            cache: {},
          },
          vi.fn()
        );
        throw new Error("Expected error to be thrown");
      } catch (e) {
        expect(e).toHaveProperty("status", 403);
        expect(e).toHaveProperty("id", "authorization_error");
        expect(errToString(e)).toContain(
          "does not have access to this resource"
        );
      }
    });

    it("should return error with invalid API key", async () => {
      const state = {} as DefaultState;
      const authMiddleware = auth();

      try {
        await authMiddleware(
          {
            // @ts-expect-error mock request
            request: {
              get: vi.fn(() => `Bearer ${randomString(38)}`),
            },
            state,
            cache: {},
          },
          vi.fn()
        );
      } catch (e) {
        expect(errToString(e)).toBe("Invalid API key");
      }
    });
  });

  describe("with OAuth access token", () => {
    it("should authenticate user with valid OAuth access token", async () => {
      const state = {} as DefaultState;
      const user = await buildUser();
      const authMiddleware = auth();
      const authentication = await buildOAuthAuthentication({
        user,
        scope: [Scope.Read],
      });

      await authMiddleware(
        {
          originalUrl: "/api/users.info",
          // @ts-expect-error mock request
          request: {
            url: "/users.info",
            get: vi.fn(() => `Bearer ${authentication.accessToken}`),
          },
          state,
          cache: {},
        },
        vi.fn()
      );
      expect(state.auth.user.id).toEqual(user.id);
    });

    it("should return error with invalid scope", async () => {
      const state = {} as DefaultState;
      const user = await buildUser();
      const authMiddleware = auth();
      const authentication = await buildOAuthAuthentication({
        user,
        scope: [Scope.Read],
      });

      try {
        await authMiddleware(
          {
            originalUrl: "/api/documents.create",
            // @ts-expect-error mock request
            request: {
              url: "/documents.create",
              get: vi.fn(() => `Bearer ${authentication.accessToken}`),
            },
            state,
            cache: {},
          },
          vi.fn()
        );
      } catch (e) {
        expect(errToString(e)).toContain(
          "does not have access to this resource"
        );
      }
    });

    it("should return error with OAuth access token in body", async () => {
      const state = {} as DefaultState;
      const user = await buildUser();
      const authMiddleware = auth();
      const authentication = await buildOAuthAuthentication({
        user,
        scope: [Scope.Read],
      });
      try {
        await authMiddleware(
          {
            originalUrl: "/api/users.info",
            request: {
              url: "/users.info",
              // @ts-expect-error mock request
              get: vi.fn(() => null),
              body: {
                token: authentication.accessToken,
              },
            },
            state,
            cache: {},
          },
          vi.fn()
        );
      } catch (e) {
        expect(errToString(e)).toContain(
          "must be passed in the Authorization header"
        );
      }
    });
  });

  it("should return error message if no auth token is available", async () => {
    const state = {} as DefaultState;
    const authMiddleware = auth();

    try {
      await authMiddleware(
        {
          // @ts-expect-error mock request
          request: {
            get: vi.fn(() => "error"),
          },
          state,
          cache: {},
        },
        vi.fn()
      );
    } catch (e) {
      expect(errToString(e)).toBe(
        'Bad Authorization header format. Format is "Authorization: Bearer <token>"'
      );
    }
  });

  it("should allow passing auth token as a GET param", async () => {
    const state = {} as DefaultState;
    const user = await buildUser();
    const authMiddleware = auth();
    await authMiddleware(
      {
        request: {
          // @ts-expect-error mock request
          get: vi.fn(() => null),
          query: {
            token: user.getSessionToken(),
          },
        },
        state,
        cache: {},
      },
      vi.fn()
    );
    expect(state.auth.user.id).toEqual(user.id);
  });

  it("should allow passing auth token in body params", async () => {
    const state = {} as DefaultState;
    const user = await buildUser();
    const authMiddleware = auth();
    await authMiddleware(
      {
        request: {
          // @ts-expect-error mock request
          get: vi.fn(() => null),
          body: {
            token: user.getSessionToken(),
          },
        },
        state,
        cache: {},
      },
      vi.fn()
    );
    expect(state.auth.user.id).toEqual(user.id);
  });

  it("should return an error for suspended users", async () => {
    const state = {} as DefaultState;
    const admin = await buildAdmin();
    const user = await buildUser({
      suspendedAt: new Date(),
      suspendedById: admin.id,
    });
    const authMiddleware = auth();
    let error;

    try {
      await authMiddleware(
        {
          // @ts-expect-error mock request
          request: {
            get: vi.fn(() => `Bearer ${user.getSessionToken()}`),
          },
          state,
          cache: {},
        },
        vi.fn()
      );
    } catch (err) {
      error = err;
    }

    expect(errToString(error)).toEqual(
      "Your access has been suspended by a workspace admin"
    );
    expect(error).toHaveProperty("errorData.adminEmail", admin.email);
  });

  it("should return an error for deleted team", async () => {
    const state = {} as DefaultState;
    const team = await buildTeam();
    const user = await buildUser({ teamId: team.id });
    await team.destroy();
    const authMiddleware = auth();
    let error;

    try {
      await authMiddleware(
        {
          // @ts-expect-error mock request
          request: {
            get: vi.fn(() => `Bearer ${user.getSessionToken()}`),
          },
          state,
          cache: {},
        },
        vi.fn()
      );
    } catch (err) {
      error = err;
    }

    expect(errToString(error)).toEqual("Invalid token");
  });

  describe("with platform JWT", () => {
    const issuer = "https://auth.example.com/application/o/outline";
    const jwksUrl = `${issuer}/jwks/`;
    let signingKey: CryptoKey;
    let jwk: Record<string, unknown>;

    beforeAll(async () => {
      const keyPair = await generateKeyPair("RS256");
      signingKey = keyPair.privateKey;
      jwk = {
        ...(await exportJWK(keyPair.publicKey)),
        kid: "platform",
        alg: "RS256",
        use: "sig",
      };
    });

    beforeEach(() => {
      server.use(http.get(jwksUrl, () => HttpResponse.json({ keys: [jwk] })));
      oidcEnv.OIDC_ISSUER_URL = issuer;
      oidcEnv.OIDC_JWT_VERIFY = true;
      oidcEnv.OIDC_JWKS_URL = jwksUrl;
    });

    const signPlatformToken = (
      email: string,
      claims: { iss: string; aud?: string }
    ) =>
      new SignJWT({ email, preferred_username: email.split("@")[0] })
        .setProtectedHeader({ alg: "RS256", kid: "platform" })
        .setIssuer(claims.iss)
        .setAudience(claims.aud ?? "outline")
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(signingKey);

    const authenticate = (token: string) => {
      const state = {} as DefaultState;
      return auth()(
        {
          // @ts-expect-error mock request
          request: {
            get: vi.fn(() => `Bearer ${token}`),
          },
          state,
          cache: {},
        },
        vi.fn()
      ).then(() => state);
    };

    it("should authenticate a token from the configured issuer", async () => {
      const user = await buildUser();
      const token = await signPlatformToken(user.email!, { iss: issuer });

      const state = await authenticate(token);

      expect(state.auth.user.id).toEqual(user.id);
      expect(state.auth.scope).toEqual(["*"]);
    });

    it("should authenticate a token whose issuer carries a trailing slash", async () => {
      const user = await buildUser();
      const token = await signPlatformToken(user.email!, {
        iss: `${issuer}/`,
      });

      const state = await authenticate(token);

      expect(state.auth.user.id).toEqual(user.id);
    });

    it("should reject a token signed for a different issuer", async () => {
      const user = await buildUser();
      const token = await signPlatformToken(user.email!, {
        iss: `${issuer}-evil`,
      });

      await expect(authenticate(token)).rejects.toMatchObject({
        message: "Invalid token",
      });
    });

    it("should reject a token for a different audience", async () => {
      const user = await buildUser();
      const token = await signPlatformToken(user.email!, {
        iss: `${issuer}/`,
        aud: "some-other-app",
      });

      await expect(authenticate(token)).rejects.toMatchObject({
        message: "Invalid JWT",
      });
    });

    it("should reject a platform token passed in the cookie", async () => {
      const user = await buildUser();
      const token = await signPlatformToken(user.email!, {
        iss: `${issuer}/`,
      });
      const { ctx } = buildCookieContext(token);

      await expect(auth()(ctx, vi.fn())).rejects.toMatchObject({
        message: "JWT must not be passed in the cookie",
      });
    });
  });

  describe("with session JWT in the cookie", () => {
    it("should authenticate an Outline session token stored in the cookie", async () => {
      const user = await buildUser();
      const { ctx, state } = buildCookieContext(user.getSessionToken());

      await auth()(ctx, vi.fn());

      expect(state.auth.user.id).toEqual(user.id);
    });
  });
});
