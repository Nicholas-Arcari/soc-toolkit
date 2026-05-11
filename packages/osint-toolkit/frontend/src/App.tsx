import { Routes, Route } from "react-router-dom";
import Sidebar from "./components/common/Sidebar";
import EthicsBanner from "./components/common/EthicsBanner";
import Dashboard from "./pages/Dashboard";
import Targets from "./pages/Targets";
import TargetDetail from "./pages/TargetDetail";
import Investigate from "./pages/Investigate";

function App() {
  return (
    <div className="flex h-screen bg-dark-bg">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <EthicsBanner />
        <div className="p-8">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/targets" element={<Targets />} />
            <Route path="/targets/:id" element={<TargetDetail />} />
            <Route path="/investigate" element={<Investigate />} />
          </Routes>
        </div>
      </main>
    </div>
  );
}

export default App;
