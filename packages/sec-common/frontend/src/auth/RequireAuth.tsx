import { ReactNode } from "react";

import { useAuth } from "./AuthContext";
import { LoginPage, LoginPageProps } from "./LoginPage";

export type RequireAuthProps = {
  children: ReactNode;
  loginProps?: LoginPageProps;
};

// Route guard: renders the login page instead of children when the
// user is unauthenticated. Shows a tiny splash during the setup-probe
// window to avoid flashing the signup form on already-configured apps.
// When the backend has auth disabled (probe 404), we render children
// directly - zero-config trusted-network installs don't get a login
// wall between them and the app.
export function RequireAuth({ children, loginProps }: RequireAuthProps) {
  const { state, loading, authEnabled } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-dark-bg text-slate-500 text-sm">
        …
      </div>
    );
  }

  if (!authEnabled) {
    return <>{children}</>;
  }

  if (!state) {
    return <LoginPage {...loginProps} />;
  }

  return <>{children}</>;
}
