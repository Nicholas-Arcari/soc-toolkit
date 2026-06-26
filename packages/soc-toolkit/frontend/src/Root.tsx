import { useLocation } from "react-router-dom";
import { RequireAuth } from "@sec-toolkit/common/auth";
import App from "./App";
import VerifyEmail from "./pages/VerifyEmail";
import ResetPassword from "./pages/ResetPassword";

// /verify is reachable without auth (the verification email links to it);
// everything else sits behind the auth gate.
export default function Root() {
  const { pathname } = useLocation();
  if (pathname === "/verify") {
    return <VerifyEmail />;
  }
  if (pathname === "/reset") {
    return <ResetPassword />;
  }
  return (
    <RequireAuth loginProps={{ title: "SOC Toolkit" }}>
      <App />
    </RequireAuth>
  );
}
