import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { AuthProvider } from "@sec-toolkit/common/auth";
import { ThemeProvider } from "@sec-toolkit/common/theme";
import Root from "./Root";
import api from "./api/client";
import "./i18n";
import "./index.css";

// `scope` keeps SOC/OSINT sessions independent if both stacks sit on
// the same origin. `api` is the axios instance every client call uses -
// the provider attaches the Authorization header + 401 handler to it.
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <ThemeProvider>
        <AuthProvider client={api} scope="soc">
          <Root />
        </AuthProvider>
      </ThemeProvider>
    </BrowserRouter>
  </React.StrictMode>
);
