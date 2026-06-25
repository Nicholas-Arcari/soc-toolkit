import type { i18n as I18nInstance } from "i18next";

/**
 * Shared i18n for the cross-app auth surface (LoginPage + RequireAuth gates).
 *
 * sec-common does NOT own an i18next instance - each consuming app
 * (soc-toolkit, osint-toolkit) initialises its own. This module ships the
 * auth translations under a dedicated `seccommon` namespace and exposes
 * `registerCommonI18n(i18n)` so each app can graft them onto its instance
 * after init. The auth components call `useTranslation("seccommon")`, so the
 * strings resolve regardless of which app mounted them.
 */
export const COMMON_NS = "seccommon";

const en = {
  login: {
    errorFailed: "authentication failed",
    heading: {
      reset: "Reset password",
      createAdmin: "Create admin account",
      createAccount: "Create your account",
      signin: "Sign in",
    },
    subtitle: {
      reset: "Enter your email and we'll send a reset link.",
      createAdmin: "Set up the first administrator for this instance.",
      trial: "Start your 7-day free trial. No card required.",
      signin: "Sign in to continue to your toolkit.",
    },
    submit: {
      reset: "Send reset link",
      createAdmin: "Create admin",
      trial: "Start free trial",
      signin: "Sign in",
    },
    forgotSentBefore: "If an account exists for ",
    thatEmail: "that email",
    forgotSentAfter: ", a reset link is on its way. Check your inbox.",
    backToSignIn: "Back to sign in",
    username: "Username",
    email: "Email",
    emailVerifyHint: "We'll send a link to verify it.",
    password: "Password",
    minChars: "Minimum 8 characters.",
    forgotPassword: "Forgot password?",
    haveAccount: "Already have an account? ",
    newHere: "New here? ",
    signinShort: "Sign in",
    createOne: "Create one — free trial",
  },
  gate: {
    verifyTitle: "Verify your email",
    verifyBodyBefore: "We sent a verification link to ",
    yourEmail: "your email",
    verifyBodyAfter: ". Click it to activate your account.",
    linkSent: "Link sent",
    sending: "Sending…",
    resendLink: "Resend link",
    signOut: "Sign out",
    licenseError: "Could not activate the license.",
    planEnded: "Your plan has ended",
    trialEnded: "Your free trial has ended",
    welcomeBack: "Welcome back, {{username}}. Redeem a license to keep going.",
    thanksTrying:
      "Thanks for trying the toolkit, {{username}}. Redeem a license to continue.",
    activateLicense: "Activate license",
  },
};

const it: typeof en = {
  login: {
    errorFailed: "autenticazione fallita",
    heading: {
      reset: "Reimposta password",
      createAdmin: "Crea account amministratore",
      createAccount: "Crea il tuo account",
      signin: "Accedi",
    },
    subtitle: {
      reset: "Inserisci la tua email e ti invieremo un link per reimpostarla.",
      createAdmin: "Configura il primo amministratore di questa istanza.",
      trial: "Inizia la tua prova gratuita di 7 giorni. Nessuna carta richiesta.",
      signin: "Accedi per continuare nel tuo toolkit.",
    },
    submit: {
      reset: "Invia link di reset",
      createAdmin: "Crea amministratore",
      trial: "Inizia la prova gratuita",
      signin: "Accedi",
    },
    forgotSentBefore: "Se esiste un account per ",
    thatEmail: "quell'email",
    forgotSentAfter: ", un link per il reset è in arrivo. Controlla la tua casella.",
    backToSignIn: "Torna all'accesso",
    username: "Nome utente",
    email: "Email",
    emailVerifyHint: "Ti invieremo un link per verificarla.",
    password: "Password",
    minChars: "Minimo 8 caratteri.",
    forgotPassword: "Password dimenticata?",
    haveAccount: "Hai già un account? ",
    newHere: "Nuovo qui? ",
    signinShort: "Accedi",
    createOne: "Creane uno — prova gratuita",
  },
  gate: {
    verifyTitle: "Verifica la tua email",
    verifyBodyBefore: "Abbiamo inviato un link di verifica a ",
    yourEmail: "la tua email",
    verifyBodyAfter: ". Cliccalo per attivare il tuo account.",
    linkSent: "Link inviato",
    sending: "Invio…",
    resendLink: "Invia di nuovo il link",
    signOut: "Esci",
    licenseError: "Impossibile attivare la licenza.",
    planEnded: "Il tuo piano è terminato",
    trialEnded: "La tua prova gratuita è terminata",
    welcomeBack:
      "Bentornato, {{username}}. Riscatta una licenza per continuare.",
    thanksTrying:
      "Grazie per aver provato il toolkit, {{username}}. Riscatta una licenza per continuare.",
    activateLicense: "Attiva licenza",
  },
};

export const commonResources = { en, it };

/**
 * Graft the shared auth translations onto an already-initialised i18next
 * instance. Idempotent and safe to call right after `i18n.init(...)`.
 */
export function registerCommonI18n(i18n: I18nInstance): void {
  i18n.addResourceBundle("en", COMMON_NS, commonResources.en, true, true);
  i18n.addResourceBundle("it", COMMON_NS, commonResources.it, true, true);
}
