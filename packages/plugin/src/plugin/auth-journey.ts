export type PluginAuthStep =
  | "organization"
  | "credentials"
  | "human_verification"
  | "authenticating"
  | "new_password"
  | "mfa_setup"
  | "mfa"
  | "recovery"
  | "local_unlock"
  | "complete";

export type PluginAuthChallengeKind = "new_password" | "mfa_setup" | "mfa" | "recovery";

export interface PluginVerificationBinding {
  attemptId: string;
  permit: string;
  expiresAt: number;
}

export type PluginLoginVerificationMode = "unresolved" | "disabled" | "observe" | "enforce";

export type PluginLoginVerificationResult =
  | { mode: "disabled" }
  | {
      mode: "observe" | "enforce";
      binding: PluginVerificationBinding;
    };

export interface PluginAuthChallenge {
  kind: PluginAuthChallengeKind;
  session: string;
}

export interface PluginAuthJourneyState {
  step: PluginAuthStep;
  generation: number;
  requireOrganization: boolean;
  loginVerificationMode: PluginLoginVerificationMode;
  loginVerificationResolverAvailable: boolean;
  encryptionMode: "server-managed" | "hybrid-zk";
  organization: string;
  email: string;
  password: string;
  newPassword: string;
  challengeAnswer: string;
  passphrase: string;
  verification: PluginVerificationBinding | null;
  challenge: PluginAuthChallenge | null;
}

export interface CreatePluginAuthJourneyOptions {
  requireOrganization: boolean;
  loginVerificationMode: PluginLoginVerificationMode;
  loginVerificationResolverAvailable?: boolean;
  encryptionMode: "server-managed" | "hybrid-zk";
  organization?: string;
  email?: string;
  generation?: number;
}

export type PluginAuthJourneyEvent =
  | { type: "confirm_organization"; organization: string }
  | { type: "submit_credentials"; email: string; password: string }
  | {
      type: "verification_accepted";
      attemptId: string;
      permit: string;
      expiresAt: number;
      mode: "observe" | "enforce";
      now?: number;
    }
  | { type: "verification_disabled" }
  | { type: "verification_expired" }
  | {
      type: "authentication_challenge";
      challenge: PluginAuthChallengeKind;
      session?: string;
    }
  | {
      type: "challenge_succeeded";
      nextChallenge?: PluginAuthChallengeKind;
      session?: string;
    }
  | { type: "authentication_succeeded" }
  | { type: "use_recovery" }
  | { type: "use_mfa" }
  | { type: "submit_local_unlock"; passphrase: string }
  | { type: "change_organization"; organization: string }
  | { type: "back" }
  | { type: "close" };

function normalizeOrganization(value: string): string {
  return value.trim().toLowerCase();
}

function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

function initialStep(options: CreatePluginAuthJourneyOptions): PluginAuthStep {
  return options.requireOrganization && !normalizeOrganization(options.organization ?? "")
    ? "organization"
    : "credentials";
}

export function createPluginAuthJourney(
  options: CreatePluginAuthJourneyOptions
): PluginAuthJourneyState {
  return {
    step: initialStep(options),
    generation: options.generation ?? 0,
    requireOrganization: options.requireOrganization,
    loginVerificationMode: options.loginVerificationMode,
    loginVerificationResolverAvailable:
      options.loginVerificationResolverAvailable ?? options.loginVerificationMode === "unresolved",
    encryptionMode: options.encryptionMode,
    organization: normalizeOrganization(options.organization ?? ""),
    email: normalizeEmail(options.email ?? ""),
    password: "",
    newPassword: "",
    challengeAnswer: "",
    passphrase: "",
    verification: null,
    challenge: null,
  };
}

function assertStep(
  state: PluginAuthJourneyState,
  event: PluginAuthJourneyEvent["type"],
  allowed: readonly PluginAuthStep[]
): void {
  if (!allowed.includes(state.step)) {
    throw new Error(`Cannot ${event} while plugin authentication is on ${state.step}.`);
  }
}

function stepForChallenge(kind: PluginAuthChallengeKind): PluginAuthStep {
  return kind;
}

function wipeSecrets(
  state: PluginAuthJourneyState,
  overrides: Partial<PluginAuthJourneyState> = {}
): PluginAuthJourneyState {
  return {
    ...state,
    password: "",
    newPassword: "",
    challengeAnswer: "",
    passphrase: "",
    verification: null,
    challenge: null,
    ...overrides,
  };
}

function completeIdentityAuthentication(
  state: PluginAuthJourneyState
): PluginAuthJourneyState {
  return wipeSecrets(state, {
    step: state.encryptionMode === "hybrid-zk" ? "local_unlock" : "complete",
  });
}

function unresolvedModeForOrganization(
  state: PluginAuthJourneyState
): PluginLoginVerificationMode {
  return state.loginVerificationResolverAvailable ? "unresolved" : "disabled";
}

export function transitionPluginAuthJourney(
  state: PluginAuthJourneyState,
  event: PluginAuthJourneyEvent
): PluginAuthJourneyState {
  switch (event.type) {
    case "confirm_organization": {
      assertStep(state, event.type, ["organization"]);
      const organization = normalizeOrganization(event.organization);
      if (!organization && state.requireOrganization) {
        throw new Error("Organization is required.");
      }
      return wipeSecrets(state, { step: "credentials", organization });
    }
    case "submit_credentials": {
      assertStep(state, event.type, ["credentials"]);
      const email = normalizeEmail(event.email);
      if (!email || !event.password) {
        throw new Error("Email and password are required.");
      }
      return {
        ...wipeSecrets(state),
        step: state.loginVerificationMode === "disabled"
          ? "authenticating"
          : "human_verification",
        email,
        password: event.password,
      };
    }
    case "verification_accepted": {
      assertStep(state, event.type, ["human_verification"]);
      if (
        state.loginVerificationMode === "disabled" ||
        (state.loginVerificationMode !== "unresolved" &&
          state.loginVerificationMode !== event.mode)
      ) {
        throw new Error("Human-verification mode does not match the resolved organization policy.");
      }
      const now = event.now ?? Date.now();
      if (!event.attemptId || !event.permit || event.expiresAt <= now) {
        throw new Error("Human verification is missing or expired.");
      }
      return {
        ...state,
        step: "authenticating",
        loginVerificationMode: event.mode,
        verification: {
          attemptId: event.attemptId,
          permit: event.permit,
          expiresAt: event.expiresAt,
        },
      };
    }
    case "verification_disabled":
      assertStep(state, event.type, ["human_verification"]);
      if (state.loginVerificationMode !== "unresolved") {
        throw new Error("Human verification cannot be disabled after a required mode was selected.");
      }
      return {
        ...state,
        step: "authenticating",
        loginVerificationMode: "disabled",
        verification: null,
      };
    case "verification_expired":
      assertStep(state, event.type, ["human_verification", "authenticating"]);
      return wipeSecrets(state, {
        step: "credentials",
        generation: state.generation + 1,
      });
    case "authentication_challenge": {
      assertStep(state, event.type, ["authenticating"]);
      return {
        ...state,
        step: stepForChallenge(event.challenge),
        password: "",
        verification: null,
        challenge: { kind: event.challenge, session: event.session ?? "" },
      };
    }
    case "challenge_succeeded": {
      assertStep(state, event.type, ["new_password", "mfa_setup", "mfa", "recovery"]);
      if (!event.nextChallenge) {
        return completeIdentityAuthentication(state);
      }
      return {
        ...state,
        step: stepForChallenge(event.nextChallenge),
        newPassword: "",
        challengeAnswer: "",
        challenge: {
          kind: event.nextChallenge,
          session: event.session ?? "",
        },
      };
    }
    case "authentication_succeeded":
      assertStep(state, event.type, ["authenticating"]);
      return completeIdentityAuthentication(state);
    case "use_recovery":
      assertStep(state, event.type, ["mfa"]);
      return {
        ...state,
        step: "recovery",
        challengeAnswer: "",
        challenge: {
          kind: "recovery",
          session: state.challenge?.session ?? "",
        },
      };
    case "use_mfa":
      assertStep(state, event.type, ["recovery"]);
      return {
        ...state,
        step: "mfa",
        challengeAnswer: "",
        challenge: {
          kind: "mfa",
          session: state.challenge?.session ?? "",
        },
      };
    case "submit_local_unlock":
      assertStep(state, event.type, ["local_unlock"]);
      if (!event.passphrase) throw new Error("Encryption passphrase is required.");
      return wipeSecrets({ ...state, passphrase: event.passphrase }, { step: "complete" });
    case "change_organization": {
      const organization = normalizeOrganization(event.organization);
      if (!organization && state.requireOrganization) {
        return wipeSecrets(state, {
          step: "organization",
          generation: state.generation + 1,
          loginVerificationMode: unresolvedModeForOrganization(state),
          organization: "",
          email: "",
        });
      }
      return wipeSecrets(state, {
        step: "credentials",
        generation: state.generation + 1,
        loginVerificationMode: unresolvedModeForOrganization(state),
        organization,
        email: "",
      });
    }
    case "back": {
      if (state.step === "credentials" && state.requireOrganization) {
        return wipeSecrets(state, {
          step: "organization",
          generation: state.generation + 1,
          loginVerificationMode: unresolvedModeForOrganization(state),
        });
      }
      if (state.step === "organization") return state;
      return wipeSecrets(state, {
        step: "credentials",
        generation: state.generation + 1,
      });
    }
    case "close":
      return createPluginAuthJourney({
        requireOrganization: state.requireOrganization,
        loginVerificationMode: state.loginVerificationMode,
        loginVerificationResolverAvailable: state.loginVerificationResolverAvailable,
        encryptionMode: state.encryptionMode,
        organization: state.organization,
        email: state.email,
        generation: state.generation + 1,
      });
  }
}

export function isPluginAuthGenerationCurrent(
  state: PluginAuthJourneyState,
  generation: number
): boolean {
  return state.generation === generation;
}
