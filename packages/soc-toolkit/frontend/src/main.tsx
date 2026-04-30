import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { AuthProvider, RequireAuth } from "@sec-toolkit/common/auth";
import App from "./App";
import api from "./api/client";
import "./index.css";

// `scope` keeps SOC/OSINT sessions independent if both stacks sit on
// the same origin. `api` is the axios instance every client call uses -
// the provider attaches the Authorization header + 401 handler to it.
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider client={api} scope="soc">
        <RequireAuth loginProps={{ title: "SOC Toolkit" }}>
          <App />
        </RequireAuth>
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>
);
