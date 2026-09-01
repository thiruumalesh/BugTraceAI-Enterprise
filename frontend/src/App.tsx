import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CalendarClock,
  Bell,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Clock3,
  Grid2X2,
  Layers3,
  Menu,
  Network,
  Plus,
  Search,
  Settings,
  ShieldCheck,
  Smartphone,
  Sparkles,
  X,
} from "lucide-react";

import "./App.css";
import ApiDast from "./pages/ApiDast";
import Mast from "./pages/Mast";
import NetworkPentest from "./pages/NetworkPentest";
import ScheduledScans from "./pages/ScheduledScans";

type ActivityRow = {
  id: string;
  target: string;
  type: string;
  status: "Completed" | "Running";
  risk: "High" | "Medium" | "Low" | "—";
  timestamp: number;
};

type Page =
  | "overview"
  | "api-dast"
  | "mast"
  | "network-pentest"
  | "scheduled-scans";

const activityRows: ActivityRow[] = [
  {
    id: "ESCN-010",
    target: "calix.com",
    type: "DAST",
    status: "Completed",
    risk: "High",
    timestamp: Date.now() - 12 * 60 * 1000,
  },
  {
    id: "ESCN-009",
    target: "API Gateway",
    type: "API",
    status: "Running",
    risk: "—",
    timestamp: Date.now() - 28 * 60 * 1000,
  },
  {
    id: "MAST-018",
    target: "CommandIQ",
    type: "MAST",
    status: "Completed",
    risk: "Medium",
    timestamp: Date.now() - 60 * 60 * 1000,
  },
  {
    id: "NET-007",
    target: "Corporate Network",
    type: "Network",
    status: "Completed",
    risk: "Low",
    timestamp: Date.now() - 3 * 60 * 60 * 1000,
  },
];

function formatRelativeTime(timestamp: number): string {
  const diffSeconds = Math.max(
    0,
    Math.floor((Date.now() - timestamp) / 1000),
  );

  if (diffSeconds < 10) {
    return "just now";
  }

  if (diffSeconds < 60) {
    return `${diffSeconds} sec ago`;
  }

  const minutes = Math.floor(diffSeconds / 60);

  if (minutes < 60) {
    return `${minutes} min ago`;
  }

  const hours = Math.floor(minutes / 60);

  if (hours < 24) {
    const remainingMinutes = minutes % 60;

    if (remainingMinutes === 0) {
      return `${hours} hour${hours === 1 ? "" : "s"} ago`;
    }

    return `${hours}h ${remainingMinutes}m ago`;
  }

  const days = Math.floor(hours / 24);

  return `${days} day${days === 1 ? "" : "s"} ago`;
}

function App() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [currentPage, setCurrentPage] = useState<Page>("overview");

  const [, setTimeTick] = useState(0);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setTimeTick((value) => value + 1);
    }, 30_000);

    return () => window.clearInterval(timer);
  }, []);

  const navigateTo = (page: Page) => {
    setCurrentPage(page);
    setSidebarOpen(false);
  };

  return (
    <div className="app-shell">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <button
          className="sidebar-overlay"
          aria-label="Close navigation"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside className={`sidebar ${sidebarOpen ? "sidebar-open" : ""}`}>
        <div className="sidebar-brand">
          <div className="brand-icon">
            <ShieldCheck size={28} strokeWidth={2.4} />
          </div>

          <div className="brand-copy">
            <div className="brand-name">CALIX</div>
            <div className="brand-subtitle">SECURITY INTELLIGENCE</div>
            <div className="brand-subtitle">PLATFORM</div>
          </div>

          <button
            className="mobile-close"
            onClick={() => setSidebarOpen(false)}
            aria-label="Close menu"
          >
            <X size={22} />
          </button>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section-label">PLATFORM</div>

          <button
            className={`nav-item ${
              currentPage === "overview" ? "active" : ""
            }`}
            onClick={() => navigateTo("overview")}
          >
            <Grid2X2 size={21} />
            <span>Security Overview</span>
          </button>

          <div className="nav-section-label">SECURITY TESTING</div>

          <button
            className={`nav-item ${
              currentPage === "api-dast" ? "active" : ""
            }`}
            onClick={() => navigateTo("api-dast")}
          >
            <ShieldCheck size={21} />
            <span>API / DAST</span>
          </button>

          <button
            className={`nav-item ${
              currentPage === "mast" ? "active" : ""
            }`}
            onClick={() => navigateTo("mast")}
          >
            <Smartphone size={21} />
            <span>MAST</span>
          </button>

          <button
            className={`nav-item ${
              currentPage === "network-pentest" ? "active" : ""
            }`}
            onClick={() => navigateTo("network-pentest")}
          >
            <Network size={21} />
            <span>Network Pentest</span>
          </button>

          <button
            className={`nav-item ${
              currentPage === "scheduled-scans" ? "active" : ""
            }`}
            onClick={() => navigateTo("scheduled-scans")}
          >
            <CalendarClock size={21} />
            <span>Scheduled Scans</span>
          </button>

          <div className="nav-section-label">INTELLIGENCE</div>

          <button className="nav-item">
            <CircleDot size={21} />
            <span>Findings</span>
          </button>

          <button className="nav-item">
            <Activity size={21} />
            <span>Reports</span>
          </button>
        </nav>

        <div className="sidebar-bottom">
          <button className="nav-item settings-item">
            <Settings size={21} />
            <span>Settings</span>
          </button>

          <div className="engine-status">
            <span className="status-dot" />
            <span>Security Engine Online</span>
          </div>
        </div>
      </aside>

      {/* Main application */}
      <div className="main-area">
        {/* Header */}
        <header className="top-header">
          <div className="header-left">
            <button
              className="mobile-menu"
              onClick={() => setSidebarOpen(true)}
              aria-label="Open menu"
            >
              <Menu size={25} />
            </button>

            <div>
              <div className="breadcrumb">
                CALIX / SECURITY INTELLIGENCE PLATFORM
              </div>

              <h1>
                {currentPage === "overview"
                  ? "Security Overview"
                  : currentPage === "api-dast"
                    ? "API / DAST"
                    : currentPage === "mast"
                      ? "MAST"
                      : currentPage === "scheduled-scans"
                        ? "Scheduled Scans"
                        : "Network Pentest"}
              </h1>
            </div>
          </div>

          <div className="header-actions">
            <button className="header-icon" aria-label="Search">
              <Search size={21} />
            </button>

            <button
              className="header-icon notification"
              aria-label="Notifications"
            >
              <Bell size={21} />
              <span />
            </button>

            <div className="user-profile">
              <div className="avatar">SE</div>

              <div className="user-copy">
                <strong>Security Engineering</strong>
                <small>CALIX ENTERPRISE</small>
              </div>
            </div>
          </div>
        </header>

        <main className="content">
          {currentPage === "overview" ? (
            <>
              {/* Page introduction */}
              <section className="page-intro">
                <div>
                  <div className="eyebrow">
                    ENTERPRISE SECURITY OPERATIONS
                  </div>

                  <h2>Security Operations Center</h2>

                  <p>
                    Unified security visibility across applications, APIs,
                    mobile platforms and network infrastructure.
                  </p>
                </div>

                <button className="primary-button">
                  <Plus size={20} />
                  New Security Assessment
                </button>
              </section>

              {/* Overview metrics */}
              <section className="overview-grid">
                <MetricCard
                  icon={<Activity size={24} />}
                  iconClass="blue"
                  label="ACTIVE ASSESSMENTS"
                  value="03"
                  detail="+1 this week"
                />

                <MetricCard
                  icon={<AlertTriangle size={24} />}
                  iconClass="red"
                  label="OPEN FINDINGS"
                  value="42"
                  detail="08 high priority"
                />

                <MetricCard
                  icon={<Layers3 size={24} />}
                  iconClass="purple"
                  label="ASSETS MONITORED"
                  value="186"
                  detail="+14 this month"
                />

                <MetricCard
                  icon={<CircleDot size={24} />}
                  iconClass="green"
                  label="SECURITY COVERAGE"
                  value="94%"
                  detail="+6.2% this quarter"
                />
              </section>

              {/* Testing domains + posture */}
              <section className="domains-layout">
                <div className="domains-section">
                  <SectionHeading
                    title="Security Testing Domains"
                    description="Select a security capability to begin an assessment."
                  />

                  <div className="engine-badge">
                    <span className="status-dot" />
                    ENGINE ONLINE
                  </div>

                  <div className="domain-grid">
                    <button
                      className="domain-card-button"
                      onClick={() => navigateTo("api-dast")}
                    >
                      <DomainCard
                        type="blue"
                        icon={<ShieldCheck size={26} />}
                        title="API / DAST"
                        description="Dynamic application and API security testing"
                        footer="121 endpoints monitored"
                      />
                    </button>

                    <button
                      className="domain-card-button"
                      onClick={() => navigateTo("mast")}
                    >
                      <DomainCard
                        type="purple"
                        icon={<Smartphone size={26} />}
                        title="MAST"
                        description="Android and iOS mobile application testing"
                        footer="18 applications assessed"
                      />
                    </button>

                    <button
                      className="domain-card-button"
                      onClick={() => navigateTo("network-pentest")}
                      type="button"
                      aria-label="Open Network Pentest"
                    >
                      <DomainCard
                        type="green"
                        icon={<Network size={26} />}
                        title="Network Pentest"
                        description="Network infrastructure and perimeter assessment"
                        footer="47 assets monitored"
                      />
                    </button>
                  </div>
                </div>

                <SecurityPosture />
              </section>

              {/* Security intelligence */}
              <section className="intelligence-section">
                <SectionHeading
                  title="Security Intelligence"
                  description="Current platform activity and security posture."
                  action="View intelligence"
                />

                <div className="intelligence-grid">
                  <IntelligenceCard
                    type="purple"
                    icon={<Sparkles size={24} />}
                    label="AI Security Analysis"
                    metric="87%"
                    description="Findings validated with AI-assisted analysis"
                  />

                  <IntelligenceCard
                    type="orange"
                    icon={<AlertTriangle size={24} />}
                    label="Priority Risk"
                    metric="08"
                    description="High-priority findings require attention"
                  />

                  <IntelligenceCard
                    type="green"
                    icon={<CheckCircle2 size={24} />}
                    label="Remediation Progress"
                    metric="76%"
                    description="Security findings successfully remediated"
                  />

                  <IntelligenceCard
                    type="blue"
                    icon={<Clock3 size={24} />}
                    label="Avg. Scan Time"
                    metric="18m"
                    description="Average assessment execution time"
                  />
                </div>
              </section>

              {/* Recent activity */}
              <section className="activity-section">
                <SectionHeading
                  title="Recent Security Activity"
                  description="Latest assessment activity across the platform."
                  action="View all"
                />

                <div className="activity-table-wrapper">
                  <table className="activity-table">
                    <thead>
                      <tr>
                        <th>SCAN ID</th>
                        <th>TARGET</th>
                        <th>TYPE</th>
                        <th>STATUS</th>
                        <th>RISK</th>
                        <th>TIME</th>
                      </tr>
                    </thead>

                    <tbody>
                      {activityRows.map((row) => (
                        <tr key={row.id}>
                          <td className="scan-id">{row.id}</td>

                          <td className="target-cell">{row.target}</td>

                          <td>
                            <span className="type-tag">{row.type}</span>
                          </td>

                          <td>
                            <span
                              className={`status-tag ${
                                row.status === "Running"
                                  ? "status-running"
                                  : "status-completed"
                              }`}
                            >
                              {row.status}
                            </span>
                          </td>

                          <td>
                            <RiskBadge risk={row.risk} />
                          </td>

                          <td className="time-cell">{formatRelativeTime(row.timestamp)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </>
          ) : currentPage === "api-dast" ? (
            <ApiDast />
          ) : currentPage === "mast" ? (
            <Mast />
          ) : currentPage === "scheduled-scans" ? (
            <ScheduledScans />
          ) : (
            <NetworkPentest />
          )}
        </main>
      </div>
    </div>
  );
}

/* ---------------- Components ---------------- */

function MetricCard({
  icon,
  iconClass,
  label,
  value,
  detail,
}: {
  icon: React.ReactNode;
  iconClass: string;
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <article className={`metric-card metric-${iconClass}`}>
      <div className={`metric-icon ${iconClass}`}>{icon}</div>

      <div className="live-badge">LIVE</div>

      <div className="metric-label">{label}</div>

      <div className="metric-value">{value}</div>

      <div className="metric-detail">{detail}</div>
    </article>
  );
}

function DomainCard({
  type,
  icon,
  title,
  description,
  footer,
}: {
  type: string;
  icon: React.ReactNode;
  title: string;
  description: string;
  footer: string;
}) {
  return (
    <article className={`domain-card domain-${type}`}>
      <div className="domain-top">
        <div className={`domain-icon ${type}`}>{icon}</div>

        <ChevronRight size={24} className="domain-arrow" />
      </div>

      <h3>{title}</h3>

      <p>{description}</p>

      <strong>{footer}</strong>
    </article>
  );
}

function SecurityPosture() {
  return (
    <article className="posture-card">
      <div className="posture-top">
        <div>
          <h3>Security Posture</h3>
          <p>Enterprise risk overview</p>
        </div>

        <div className="posture-score">
          86<span>/100</span>
        </div>
      </div>

      <div className="progress-track">
        <div className="progress-value" />
      </div>

      <div className="overall-posture">
        <span className="green-dot" />
        <span>Overall posture:</span>
        <strong>Good</strong>
      </div>

      <div className="risk-grid">
        <RiskCount color="red" label="Critical" value="01" />
        <RiskCount color="orange" label="High" value="08" />
        <RiskCount color="yellow" label="Medium" value="21" />
        <RiskCount color="green" label="Low" value="12" />
      </div>

      <button className="review-button">
        Review Risk Exposure
        <ChevronRight size={19} />
      </button>
    </article>
  );
}

function RiskCount({
  color,
  label,
  value,
}: {
  color: string;
  label: string;
  value: string;
}) {
  return (
    <div className="risk-count">
      <div>
        <span className={`risk-dot ${color}`} />
        <strong>{label}</strong>
      </div>

      <strong className={`risk-number ${color}`}>{value}</strong>
    </div>
  );
}

function IntelligenceCard({
  type,
  icon,
  label,
  metric,
  description,
}: {
  type: string;
  icon: React.ReactNode;
  label: string;
  metric: string;
  description: string;
}) {
  return (
    <article className={`intelligence-card intelligence-${type}`}>
      <div className={`intelligence-icon ${type}`}>{icon}</div>

      <div className="intelligence-content">
        <div className="intelligence-label">{label}</div>

        <div className="intelligence-metric">{metric}</div>

        <div className="intelligence-description">
          {description}
        </div>
      </div>
    </article>
  );
}

function RiskBadge({ risk }: { risk: ActivityRow["risk"] }) {
  if (risk === "—") {
    return <span className="risk-empty">—</span>;
  }

  return (
    <span className={`risk-badge risk-${risk.toLowerCase()}`}>
      {risk}
    </span>
  );
}

function SectionHeading({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: string;
}) {
  return (
    <div className="section-heading">
      <div>
        <h2>{title}</h2>
        <p>{description}</p>
      </div>

      {action && (
        <button className="section-action">
          {action}
          <ChevronRight size={18} />
        </button>
      )}
    </div>
  );
}

export default App;
