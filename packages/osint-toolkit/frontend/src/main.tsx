import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { AuthProvider, RequireAuth } from "@sec-toolkit/common/auth";
import { ThemeProvider } from "@sec-toolkit/common/theme";
import App from "./App";
import api from "./api/client";
import "./index.css";
import "./i18n";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <ThemeProvider>
        <AuthProvider client={api} scope="osint">
          <RequireAuth loginProps={{ title: "OSINT Toolkit" }}>
            <App />
          </RequireAuth>
        </AuthProvider>
      </ThemeProvider>
    </BrowserRouter>
  </React.StrictMode>
);
