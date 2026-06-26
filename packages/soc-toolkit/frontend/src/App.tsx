import { lazy, Suspense } from "react";
import { Routes, Route } from "react-router-dom";
import Sidebar from "./components/common/Sidebar";
import DisclaimerGate from "./components/common/DisclaimerGate";
import LevelUpToast from "./components/common/LevelUpToast";

// Code-split every route so the initial bundle doesn't pull in WeasyPrint-
// heavy PDF preview code, cytoscape, or yara/sigma matchers unless the
// user navigates to those pages. Dashboard is small enough to stay eager.
import Dashboard from "./pages/Dashboard";

const PhishingAnalyzer = lazy(() => import("./pages/PhishingAnalyzer"));
const LogAnalyzer = lazy(() => import("./pages/LogAnalyzer"));
const IOCExtractor = lazy(() => import("./pages/IOCExtractor"));
const IOCPivot = lazy(() => import("./pages/IOCPivot"));
const YaraScan = lazy(() => import("./pages/YaraScan"));
const SigmaDetection = lazy(() => import("./pages/SigmaDetection"));
const MISPEnrichment = lazy(() => import("./pages/MISPEnrichment"));
const Profile = lazy(() => import("./pages/Profile"));
const Contact = lazy(() => import("./pages/Contact"));
const Settings = lazy(() => import("./pages/Settings"));
const News = lazy(() => import("./pages/News"));
const FileInspector = lazy(() => import("./pages/FileInspector"));
const QrAnalyzer = lazy(() => import("./pages/QrAnalyzer"));
const LinkAnalyzer = lazy(() => import("./pages/LinkAnalyzer"));

function PageFallback() {
  return (
    <div className="flex h-full items-center justify-center text-sm text-muted">
      Loading…
    </div>
  );
}

function App() {
  return (
    <div className="flex h-screen bg-background text-foreground">
      <DisclaimerGate />
      <LevelUpToast />
      <Sidebar />
      <main className="flex-1 overflow-y-auto p-8">
        <Suspense fallback={<PageFallback />}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/phishing" element={<PhishingAnalyzer />} />
            <Route path="/logs" element={<LogAnalyzer />} />
            <Route path="/ioc" element={<IOCExtractor />} />
            <Route path="/ioc-pivot" element={<IOCPivot />} />
            <Route path="/yara" element={<YaraScan />} />
            <Route path="/sigma" element={<SigmaDetection />} />
            <Route path="/misp" element={<MISPEnrichment />} />
            <Route path="/file" element={<FileInspector />} />
            <Route path="/qr" element={<QrAnalyzer />} />
            <Route path="/link" element={<LinkAnalyzer />} />
            <Route path="/profile" element={<Profile />} />
            <Route path="/contact" element={<Contact />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/news" element={<News />} />
          </Routes>
        </Suspense>
      </main>
    </div>
  );
}

export default App;
