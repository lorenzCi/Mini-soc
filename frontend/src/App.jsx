import { Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import Packets from "./pages/Packets";
import Rules from "./pages/Rules";
import Stats from "./pages/Stats";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="packets" element={<Packets />} />
        <Route path="rules" element={<Rules />} />
        <Route path="stats" element={<Stats />} />
      </Route>
    </Routes>
  );
}
