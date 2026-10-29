import React, { useState } from "react";
import { AppProvider } from "./store.js";
import { DashboardPage } from "./pages/DashboardPage.js";
import { TargetPage } from "./pages/TargetPage.js";
import { ScannerPage } from "./pages/ScannerPage.js";
import { RepeaterPage } from "./pages/RepeaterPage.js";
import { AnalyzerPage } from "./pages/AnalyzerPage.js";
import { ProxyPage } from "./pages/ProxyPage.js";
import { ReportPage } from "./pages/ReportPage.js";

const TABS = [
  { key: "dashboard", label: "Dashboard" },
  { key: "target", label: "Target" },
  { key: "scanner", label: "Scanner" },
  { key: "repeater", label: "Repeater" },
  { key: "analyzer", label: "Analyzer" },
  { key: "proxy", label: "Proxy" },
  { key: "report", label: "Report" },
];

function Shell() {
  const [tab, setTab] = useState("dashboard");
  const go = (t: string) => setTab(t);

  return (
    <div className="app">
      <aside className="rail">
        <div className="logo" title="GraphQL Security Suite">
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
            <circle cx="12" cy="3" r="1.6" />
            <circle cx="20" cy="7.5" r="1.6" />
            <circle cx="20" cy="16.5" r="1.6" />
            <circle cx="12" cy="21" r="1.6" />
            <circle cx="4" cy="16.5" r="1.6" />
            <circle cx="4" cy="7.5" r="1.6" />
            <path d="M12 4.6 19 7.5 19 16.5 12 19.4 5 16.5 5 7.5Z" />
          </svg>
        </div>
        <div className="rail-icon">graphql · sec</div>
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="brand">
            GQL<span className="dot">·</span>SEC
          </div>
          <nav className="tabs">
            {TABS.map((t) => (
              <button key={t.key} className={tab === t.key ? "active" : ""} onClick={() => setTab(t.key)}>
                {t.label}
              </button>
            ))}
          </nav>
        </header>

        {tab === "dashboard" && <DashboardPage go={go} />}
        {tab === "target" && <TargetPage go={go} />}
        {tab === "scanner" && <ScannerPage go={go} />}
        {tab === "repeater" && <RepeaterPage go={go} />}
        {tab === "analyzer" && <AnalyzerPage />}
        {tab === "proxy" && <ProxyPage />}
        {tab === "report" && <ReportPage go={go} />}
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AppProvider>
      <Shell />
    </AppProvider>
  );
}
