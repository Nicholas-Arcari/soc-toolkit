import { Routes, Route } from "react-router-dom";
import Sidebar from "./components/common/Sidebar";
import Dashboard from "./pages/Dashboard";
import PhishingAnalyzer from "./pages/PhishingAnalyzer";
import LogAnalyzer from "./pages/LogAnalyzer";
import IOCExtractor from "./pages/IOCExtractor";

function App() {
  return (
    <div className="flex h-screen bg-dark-bg">
      <Sidebar />
      <main className="flex-1 overflow-y-auto p-8">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/phishing" element={<PhishingAnalyzer />} />
          <Route path="/logs" element={<LogAnalyzer />} />
          <Route path="/ioc" element={<IOCExtractor />} />
        </Routes>
      </main>
    </div>
  );
}

export default App;
