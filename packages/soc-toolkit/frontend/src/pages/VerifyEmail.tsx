import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { CheckCircle, XCircle } from "lucide-react";
import { verifyEmail } from "../api/client";

// Public page (outside the auth gate) that the verification email links to.
// Confirms the token server-side, then sends the user on to sign in.
export default function VerifyEmail() {
  const { t } = useTranslation();
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const [status, setStatus] = useState<"verifying" | "ok" | "error">(
    "verifying",
  );
  const ran = useRef(false);

  useEffect(() => {
    if (ran.current) return; // StrictMode double-invoke guard
    ran.current = true;
    if (!token) {
      setStatus("error");
      return;
    }
    verifyEmail(token)
      .then(() => setStatus("ok"))
      .catch(() => setStatus("error"));
  }, [token]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-background px-4">
      <div className="w-full max-w-md bg-card border border-border rounded-2xl p-8 text-center space-y-4 shadow-xl">
        {status === "verifying" && (
          <p className="text-muted">{t("auth.verifying")}</p>
        )}

        {status === "ok" && (
          <>
            <div className="mx-auto w-12 h-12 rounded-xl bg-emerald-500/10 flex items-center justify-center">
              <CheckCircle className="w-6 h-6 text-emerald-400" />
            </div>
            <h1 className="text-xl font-semibold text-foreground">
              {t("auth.verifiedTitle")}
            </h1>
            <p className="text-sm text-muted">{t("auth.verifiedBody")}</p>
            <Link
              to="/"
              className="inline-block w-full rounded-lg bg-foreground text-background hover:opacity-90 text-sm font-medium py-2.5 transition-opacity"
            >
              {t("auth.continue")}
            </Link>
          </>
        )}

        {status === "error" && (
          <>
            <div className="mx-auto w-12 h-12 rounded-xl bg-red-500/10 flex items-center justify-center">
              <XCircle className="w-6 h-6 text-red-400" />
            </div>
            <h1 className="text-xl font-semibold text-foreground">
              {t("auth.verifyFailedTitle")}
            </h1>
            <p className="text-sm text-muted">{t("auth.verifyFailedBody")}</p>
            <Link
              to="/"
              className="inline-block w-full rounded-lg border border-border text-muted hover:text-foreground hover:bg-foreground/5 text-sm font-medium py-2.5 transition-colors"
            >
              {t("auth.goToSignIn")}
            </Link>
          </>
        )}
      </div>
    </div>
  );
}
