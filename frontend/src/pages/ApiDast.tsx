import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Download,
  FileText,
  LoaderCircle,
  Network,
  Plus,
  ShieldCheck,
  Sparkles,
  Square,
  XCircle,
} from "lucide-react";

import {
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import {
  createScan,
  getScanStatus,
  listScans,
  stopScan,
  type ScanStatus,
  type ScanStatusResponse,
  type ScanSummary,
} from "../services/bugtraceApi";

import ScanDetails from "../components/ScanDetails";

import "./ApiDast.css";

type AssessmentType =
  | "API Security"
  | "Web Application DAST"
  | "Full API + DAST";

type ScanDepth =
  | "quick"
  | "standard"
  | "thorough";

type AuthType =
  | "No Authentication"
  | "Bearer Token";

type AssessmentLabel =
  | "API"
  | "DAST";

function formatStatus(status: ScanStatus) {
  return (
    status.charAt(0) +
    status.slice(1).toLowerCase()
  );
}

function isActiveStatus(status: ScanStatus) {
  return [
    "PENDING",
    "INITIALIZING",
    "RUNNING",
    "PAUSED",
  ].includes(status);
}

function statusClass(status: ScanStatus) {
  if (status === "COMPLETED") return "completed";

  if (
    status === "FAILED" ||
    status === "CANCELLED"
  ) {
    return "failed";
  }

  if (status === "PAUSED") return "paused";

  return "running";
}

/*
 * BugTraceAI currently receives "full" for API Security,
 * Web Application DAST and Full API + DAST.
 *
 * Therefore the backend does not give us a native
 * assessment-type field to distinguish historical scans.
 *
 * For newly-created scans we store the selected UI type
 * locally so the GUI can correctly display:
 *
 * API-001
 * DAST-002
 */
function assessmentStorageKey(scanId: number) {
  return `calixai-assessment-type-${scanId}`;
}

function getAssessmentLabel(
  scanId: number,
): AssessmentLabel {
  try {
    const stored = localStorage.getItem(
      assessmentStorageKey(scanId),
    );

    if (stored === "API") {
      return "API";
    }

    if (stored === "DAST") {
      return "DAST";
    }
  } catch {
    // Ignore localStorage errors.
  }

  /*
   * Existing "full" scans cannot be distinguished
   * retrospectively because the backend currently returns
   * scan_type = full for all three UI assessment modes.
   *
   * DAST is the safer display for the combined/full
   * security assessment.
   */
  return "DAST";
}

function saveAssessmentLabel(
  scanId: number,
  assessmentType: AssessmentType,
) {
  let label: AssessmentLabel = "DAST";

  if (assessmentType === "API Security") {
    label = "API";
  }

  if (
    assessmentType === "Web Application DAST" ||
    assessmentType === "Full API + DAST"
  ) {
    label = "DAST";
  }

  try {
    localStorage.setItem(
      assessmentStorageKey(scanId),
      label,
    );
  } catch {
    // Ignore localStorage errors.
  }

  return label;
}

function getAssessmentId(
  scanId: number,
): string {
  const label = getAssessmentLabel(scanId);

  return `${label}-${String(scanId).padStart(
    3,
    "0",
  )}`;
}

function mapAssessmentToScanType(
  assessmentType: AssessmentType,
) {
  switch (assessmentType) {
    case "API Security":
      return "full";

    case "Web Application DAST":
      return "full";

    case "Full API + DAST":
      return "full";

    default:
      return "full";
  }
}

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
    <article className="api-metric-card">
      <div
        className={`api-metric-icon ${iconClass}`}
      >
        {icon}
      </div>

      <div className="api-metric-live">
        LIVE
      </div>

      <div className="api-metric-label">
        {label}
      </div>

      <div className="api-metric-value">
        {value}
      </div>

      <div className="api-metric-detail">
        {detail}
      </div>
    </article>
  );
}

function SeverityCard({
  label,
  value,
  type,
  width,
  description,
}: {
  label: string;
  value: string;
  type: string;
  width: string;
  description: string;
}) {
  return (
    <article
      className={`api-severity-card ${type}`}
    >
      <div className="api-severity-top">
        <div className="api-severity-name">
          <span
            className={`api-severity-dot ${type}`}
          />
          {label}
        </div>

        <strong>{value}</strong>
      </div>

      <div className="api-severity-description">
        {description}
      </div>

      <div className="api-severity-bar">
        <span
          className={`api-severity-fill ${type}`}
          style={{ width }}
        />
      </div>
    </article>
  );
}

function CoverageCard({
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
    <article
      className={`api-coverage-card ${type}`}
    >
      <div className="api-coverage-icon">
        {icon}
      </div>

      <div className="api-coverage-label">
        {label}
      </div>

      <div className="api-coverage-metric">
        {metric}
      </div>

      <div className="api-coverage-description">
        {description}
      </div>
    </article>
  );
}

function ScanStatusBadge({
  status,
}: {
  status: ScanStatus;
}) {
  return (
    <span
      className={`api-status-tag ${statusClass(
        status,
      )}`}
    >
      {status === "RUNNING" && (
        <span className="api-status-pulse" />
      )}

      {formatStatus(status)}
    </span>
  );
}

export default function ApiDast() {
  const [targetUrl, setTargetUrl] =
    useState("");

  const [assessmentType, setAssessmentType] =
    useState<AssessmentType>("API Security");

  const [authType, setAuthType] =
    useState<AuthType>("No Authentication");

  const [authToken, setAuthToken] =
    useState("");

  const [scanDepth, setScanDepth] =
    useState<ScanDepth>("standard");

  const [maxDepth, setMaxDepth] =
    useState(2);

  const [maxUrls, setMaxUrls] =
    useState(20);

  const [scans, setScans] =
    useState<ScanSummary[]>([]);

  const [liveStatuses, setLiveStatuses] =
    useState<
      Record<number, ScanStatusResponse>
    >({});

  const [
    isLoadingScans,
    setIsLoadingScans,
  ] = useState(true);

  const [isStarting, setIsStarting] =
    useState(false);

  const [
    stoppingScanId,
    setStoppingScanId,
  ] = useState<number | null>(null);

  const [error, setError] =
    useState("");

  const [
    successMessage,
    setSuccessMessage,
  ] = useState("");

  const [
    selectedScanId,
    setSelectedScanId,
  ] = useState<number | null>(null);

  const pollingRef =
    useRef<number | null>(null);

  const loadScans =
    useCallback(async () => {
      try {
        setIsLoadingScans(true);
        setError("");

        const response =
          await listScans();

        setScans(response.scans);

        const activeScans =
          response.scans.filter((scan) =>
            isActiveStatus(scan.status),
          );

        if (activeScans.length > 0) {
          const statuses =
            await Promise.all(
              activeScans.map(
                async (scan) => {
                  try {
                    return await getScanStatus(
                      scan.scan_id,
                    );
                  } catch {
                    return null;
                  }
                },
              ),
            );

          const statusMap: Record<
            number,
            ScanStatusResponse
          > = {};

          statuses.forEach((status) => {
            if (status) {
              statusMap[
                status.scan_id
              ] = status;
            }
          });

          setLiveStatuses(statusMap);
        }
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Unable to load CalixAI scans.",
        );
      } finally {
        setIsLoadingScans(false);
      }
    }, []);

  useEffect(() => {
    loadScans();
  }, [loadScans]);

  useEffect(() => {
    if (pollingRef.current) {
      window.clearInterval(
        pollingRef.current,
      );
    }

    pollingRef.current =
      window.setInterval(
        async () => {
          const activeScans =
            scans.filter((scan) =>
              isActiveStatus(scan.status),
            );

          if (
            activeScans.length === 0
          ) {
            return;
          }

          const statuses =
            await Promise.all(
              activeScans.map(
                async (scan) => {
                  try {
                    return await getScanStatus(
                      scan.scan_id,
                    );
                  } catch {
                    return null;
                  }
                },
              ),
            );

          const statusMap: Record<
            number,
            ScanStatusResponse
          > = {};

          statuses.forEach((status) => {
            if (status) {
              statusMap[
                status.scan_id
              ] = status;
            }
          });

          setLiveStatuses(statusMap);

          const hasFinishedScan =
            statuses.some(
              (status) =>
                status &&
                [
                  "COMPLETED",
                  "FAILED",
                  "STOPPED",
                  "CANCELLED",
                ].includes(
                  status.status,
                ),
            );

          if (hasFinishedScan) {
            await loadScans();
          }
        },
        2500,
      );

    return () => {
      if (pollingRef.current) {
        window.clearInterval(
          pollingRef.current,
        );
      }
    };
  }, [scans, loadScans]);

  async function handleStartAssessment() {
    setError("");
    setSuccessMessage("");

    const trimmedTarget =
      targetUrl.trim();

    if (!trimmedTarget) {
      setError(
        "Target URL / API Endpoint is required.",
      );
      return;
    }

    try {
      new URL(trimmedTarget);
    } catch {
      setError(
        "Please enter a valid URL, for example https://api.example.com",
      );
      return;
    }

    if (
      authType === "Bearer Token" &&
      !authToken.trim()
    ) {
      setError(
        "Bearer Token authentication requires an auth token.",
      );
      return;
    }

    try {
      setIsStarting(true);

      const scan =
        await createScan({
          target_url:
            trimmedTarget,

          scan_type:
            mapAssessmentToScanType(
              assessmentType,
            ),

          scan_depth: scanDepth,

          safe_mode: true,

          max_depth: maxDepth,

          max_urls: maxUrls,

          resume: false,

          use_vertical: true,

          auth_token:
            authType ===
            "Bearer Token"
              ? authToken.trim()
              : null,
        });

      const label =
        saveAssessmentLabel(
          scan.scan_id,
          assessmentType,
        );

      setLiveStatuses(
        (current) => ({
          ...current,
          [scan.scan_id]:
            scan,
        }),
      );

      setSuccessMessage(
        `${label}-${String(
          scan.scan_id,
        ).padStart(
          3,
          "0",
        )} assessment created successfully.`,
      );

      setTargetUrl("");
      setAuthToken("");

      await loadScans();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to create assessment.",
      );
    } finally {
      setIsStarting(false);
    }
  }

  async function handleStopScan(
    scanId: number,
  ) {
    try {
      setStoppingScanId(
        scanId,
      );

      setError("");

      await stopScan(scanId);

      await loadScans();

      const status =
        await getScanStatus(
          scanId,
        );

      setLiveStatuses(
        (current) => ({
          ...current,
          [scanId]: status,
        }),
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to stop the assessment.",
      );
    } finally {
      setStoppingScanId(
        null,
      );
    }
  }

  const activeScans =
    scans.filter((scan) =>
      isActiveStatus(scan.status),
    );

  const openFindings =
    scans.reduce(
      (total, scan) =>
        total +
        (liveStatuses[
          scan.scan_id
        ]?.findings_count ??
          scan.findings_count ??
          0),
      0,
    );

  /*
   * This is intentionally calculated from the
   * scan status/list until a scan is selected.
   * The detailed findings panel uses the actual
   * /findings endpoint.
   */
  const criticalFindings = 0;

  return (
    <main className="api-dast-page">

      {/* PAGE HEADER */}

      <section className="api-page-header">

        <div>
          <div className="api-eyebrow">
            API & APPLICATION SECURITY
          </div>

          <h1>
            API / DAST Security Assessment
          </h1>

          <p>
            Dynamic application and API
            security testing across
            enterprise applications,
            services and endpoints.
          </p>
        </div>

        <button
          className="api-primary-button"
          onClick={() =>
            document
              .getElementById(
                "new-assessment",
              )
              ?.scrollIntoView({
                behavior:
                  "smooth",
                block: "start",
              })
          }
        >
          <Plus size={21} />
          New Assessment
        </button>

      </section>

      {/* ERROR */}

      {error && (
        <div className="api-alert api-alert-error">
          <XCircle size={21} />
          <span>{error}</span>
        </div>
      )}

      {/* SUCCESS */}

      {successMessage && (
        <div className="api-alert api-alert-success">
          <CheckCircle2 size={21} />
          <span>
            {successMessage}
          </span>
        </div>
      )}

      {/* METRICS */}

      <section className="api-metrics-grid">

        <MetricCard
          icon={
            <Activity size={26} />
          }
          iconClass="blue"
          label="ACTIVE DAST SCANS"
          value={String(
            activeScans.length,
          ).padStart(2, "0")}
          detail={
            activeScans.length
              ? `${activeScans.length} assessment${
                  activeScans.length ===
                  1
                    ? ""
                    : "s"
                } running`
              : "No active scans"
          }
        />

        <MetricCard
          icon={
            <Network size={26} />
          }
          iconClass="purple"
          label="TOTAL SCANS"
          value={String(
            scans.length,
          ).padStart(2, "0")}
          detail="CalixAI assessments"
        />

        <MetricCard
          icon={
            <AlertTriangle
              size={26}
            />
          }
          iconClass="red"
          label="OPEN FINDINGS"
          value={String(
            openFindings,
          ).padStart(2, "0")}
          detail="From current scan results"
        />

        <MetricCard
          icon={
            <ShieldCheck
              size={26}
            />
          }
          iconClass="green"
          label="CRITICAL FINDINGS"
          value={String(
            criticalFindings,
          ).padStart(2, "0")}
          detail="Select a completed scan"
        />

      </section>

      {/* NEW ASSESSMENT */}

      <section
        className="api-assessment-card"
        id="new-assessment"
      >

        <div className="api-section-header">

          <div>
            <h2>
              New Security Assessment
            </h2>

            <p>
              Configure and launch a real
              CalixAI API / DAST security
              assessment.
            </p>
          </div>

          <div className="api-engine-badge">
            <span />
            CALIXAI ENGINE ONLINE
          </div>

        </div>

        <div className="api-form-grid">

          <label className="api-form-field api-field-wide">

            <span>
              Target URL / API Endpoint
              <b>*</b>
            </span>

            <input
              type="url"
              value={targetUrl}
              onChange={(event) =>
                setTargetUrl(
                  event.target.value,
                )
              }
              placeholder="https://api.example.com"
              disabled={isStarting}
            />

          </label>

          <label className="api-form-field">

            <span>
              Assessment Type
            </span>

            <select
              value={assessmentType}
              onChange={(event) =>
                setAssessmentType(
                  event.target
                    .value as AssessmentType,
                )
              }
              disabled={isStarting}
            >
              <option>
                API Security
              </option>

              <option>
                Web Application DAST
              </option>

              <option>
                Full API + DAST
              </option>
            </select>

          </label>

          <label className="api-form-field">

            <span>
              Authentication
            </span>

            <select
              value={authType}
              onChange={(event) =>
                setAuthType(
                  event.target
                    .value as AuthType,
                )
              }
              disabled={isStarting}
            >
              <option>
                No Authentication
              </option>

              <option>
                Bearer Token
              </option>
            </select>

          </label>

          {authType ===
            "Bearer Token" && (
            <label className="api-form-field api-field-wide">

              <span>
                Bearer Token
              </span>

              <input
                type="password"
                value={authToken}
                onChange={(event) =>
                  setAuthToken(
                    event.target
                      .value,
                  )
                }
                placeholder="Enter pre-authenticated Bearer token"
                disabled={isStarting}
              />

            </label>
          )}

          <label className="api-form-field">

            <span>
              Scan Profile
            </span>

            <select
              value={scanDepth}
              onChange={(event) =>
                setScanDepth(
                  event.target
                    .value as ScanDepth,
                )
              }
              disabled={isStarting}
            >
              <option value="quick">
                Quick Assessment
              </option>

              <option value="standard">
                Standard Assessment
              </option>

              <option value="thorough">
                Thorough Assessment
              </option>
            </select>

          </label>

          <label className="api-form-field">

            <span>
              Scanner
            </span>

            <select
              defaultValue="CalixAI DAST Engine"
              disabled={isStarting}
            >
              <option>
                CalixAI DAST Engine
              </option>

              <option>
                Burp Suite Enterprise
              </option>

              <option>
                OWASP ZAP
              </option>
            </select>

          </label>

          <label className="api-form-field">

            <span>
              Max Crawl Depth
            </span>

            <input
              type="number"
              min={1}
              max={10}
              value={maxDepth}
              onChange={(event) =>
                setMaxDepth(
                  Math.max(
                    1,
                    Number(
                      event.target
                        .value,
                    ),
                  ),
                )
              }
              disabled={isStarting}
            />

          </label>

          <label className="api-form-field">

            <span>
              Maximum URLs
            </span>

            <input
              type="number"
              min={1}
              max={1000}
              value={maxUrls}
              onChange={(event) =>
                setMaxUrls(
                  Math.max(
                    1,
                    Number(
                      event.target
                        .value,
                    ),
                  ),
                )
              }
              disabled={isStarting}
            />

          </label>

        </div>

        <div className="api-form-actions">

          <button
            className="api-secondary-button"
            onClick={() => {
              setTargetUrl("");
              setAuthToken("");
              setError("");
              setSuccessMessage("");
            }}
            disabled={isStarting}
          >
            Clear
          </button>

          <button
            className="api-primary-button"
            onClick={
              handleStartAssessment
            }
            disabled={isStarting}
          >
            {isStarting ? (
              <>
                <LoaderCircle
                  size={20}
                  className="api-spin"
                />
                Starting...
              </>
            ) : (
              <>
                <Activity
                  size={20}
                />
                Start Assessment
              </>
            )}
          </button>

        </div>

      </section>

      {/* ASSESSMENTS */}

      <section className="api-panel api-active-panel">

        <div className="api-section-header">

          <div>
            <h2>
              Security Assessments
            </h2>

            <p>
              Live and completed security
              assessments from the CalixAI
              engine.
            </p>
          </div>

          <button
            className="api-panel-action"
            onClick={loadScans}
            disabled={
              isLoadingScans
            }
          >
            {isLoadingScans ? (
              <LoaderCircle
                size={17}
                className="api-spin"
              />
            ) : (
              "Refresh"
            )}

            {!isLoadingScans && (
              <ChevronRight
                size={18}
              />
            )}
          </button>

        </div>

        <div className="api-table-container">

          <table className="api-table">

            <thead>
              <tr>
                <th>
                  SCAN ID
                </th>

                <th>
                  TARGET
                </th>

                <th>
                  TYPE
                </th>

                <th>
                  STATUS
                </th>

                <th>
                  PHASE
                </th>

                <th>
                  PROGRESS
                </th>

                <th>
                  FINDINGS
                </th>

                <th>
                  ACTION
                </th>
              </tr>
            </thead>

            <tbody>

              {isLoadingScans ? (
                <tr>
                  <td
                    colSpan={8}
                    className="api-table-empty"
                  >
                    <LoaderCircle
                      size={24}
                      className="api-spin"
                    />

                    Loading CalixAI
                    assessments...
                  </td>
                </tr>
              ) : scans.length ===
                0 ? (
                <tr>
                  <td
                    colSpan={8}
                    className="api-table-empty"
                  >
                    <ShieldCheck
                      size={26}
                    />

                    No assessments
                    found. Start a
                    new assessment
                    above.
                  </td>
                </tr>
              ) : (
                scans.map((scan) => {
                  const live =
                    liveStatuses[
                      scan.scan_id
                    ];

                  const progress =
                    live?.progress ??
                    scan.progress ??
                    0;

                  const status =
                    live?.status ??
                    scan.status;

                  const findings =
                    live?.findings_count ??
                    scan.findings_count ??
                    0;

                  const assessmentId =
                    getAssessmentId(
                      scan.scan_id,
                    );

                  const assessmentLabel =
                    getAssessmentLabel(
                      scan.scan_id,
                    );

                  return (
                    <tr
                      key={
                        scan.scan_id
                      }
                    >

                      <td className="api-scan-id">
                        {assessmentId}
                      </td>

                      <td className="api-target">
                        {scan.target}
                      </td>

                      <td>
                        <span
                          className={`api-type-tag ${
                            assessmentLabel ===
                            "API"
                              ? "api"
                              : "dast"
                          }`}
                        >
                          {assessmentLabel ===
                          "API"
                            ? "API SECURITY"
                            : "DAST"}
                        </span>
                      </td>

                      <td>
                        <ScanStatusBadge
                          status={
                            status
                          }
                        />
                      </td>

                      <td>
                        <span className="api-phase">
                          {live?.phase ??
                            (status ===
                            "COMPLETED"
                              ? "COMPLETE"
                              : "—")}
                        </span>
                      </td>

                      <td>
                        <div className="api-progress-wrapper">

                          <div className="api-progress">
                            <span
                              style={{
                                width: `${
                                  status ===
                                  "COMPLETED"
                                    ? 100
                                    : Math.min(
                                        100,
                                        Math.max(
                                          0,
                                          progress,
                                        ),
                                      )
                                }%`,
                              }}
                            />
                          </div>

                          <strong>
                            {status ===
                            "COMPLETED"
                              ? 100
                              : progress}
                            %
                          </strong>

                        </div>
                      </td>

                      <td>
                        <strong className="api-findings-count">
                          {findings}
                        </strong>
                      </td>

                      <td>

                        {isActiveStatus(
                          status,
                        ) ? (
                          <button
                            className="api-stop-button"
                            onClick={() =>
                              handleStopScan(
                                scan.scan_id,
                              )
                            }
                            disabled={
                              stoppingScanId ===
                              scan.scan_id
                            }
                            title="Stop assessment"
                          >
                            {stoppingScanId ===
                            scan.scan_id ? (
                              <LoaderCircle
                                size={17}
                                className="api-spin"
                              />
                            ) : (
                              <Square
                                size={15}
                                fill="currentColor"
                              />
                            )}

                            Stop
                          </button>
                        ) : (
                          <div className="api-completed-actions">

                            <button
                              className="api-view-button"
                              onClick={() =>
                                setSelectedScanId(
                                  scan.scan_id,
                                )
                              }
                              title="View security issues"
                            >
                              <FileText
                                size={16}
                              />
                              Issues
                            </button>

                            <button
                              className="api-download-button"
                              onClick={() =>
                                setSelectedScanId(
                                  scan.scan_id,
                                )
                              }
                              title="View issues and download report"
                            >
                              <Download
                                size={16}
                              />
                              Report
                            </button>

                          </div>
                        )}

                      </td>

                    </tr>
                  );
                })
              )}

            </tbody>

          </table>

        </div>

      </section>

      {/* FINDINGS + COVERAGE */}

      <section className="api-two-column-grid">

        <div className="api-panel">

          <div className="api-section-header">

            <div>
              <h2>
                Findings by Severity
              </h2>

              <p>
                Select a completed assessment
                to view real CalixAI findings
                and detailed security issues.
              </p>
            </div>

          </div>

          <div className="api-severity-grid">

            <SeverityCard
              label="Critical"
              value="—"
              type="critical"
              width="0%"
              description="Select an assessment to load findings"
            />

            <SeverityCard
              label="High"
              value="—"
              type="high"
              width="0%"
              description="Select an assessment to load findings"
            />

            <SeverityCard
              label="Medium"
              value="—"
              type="medium"
              width="0%"
              description="Select an assessment to load findings"
            />

            <SeverityCard
              label="Low"
              value="—"
              type="low"
              width="0%"
              description="Select an assessment to load findings"
            />

          </div>

          <button
            className="api-review-button"
            onClick={() => {
              const completed =
                scans.find(
                  (scan) =>
                    scan.status ===
                    "COMPLETED",
                );

              if (completed) {
                setSelectedScanId(
                  completed.scan_id,
                );
              }
            }}
          >
            View Security Findings
            <ChevronRight
              size={19}
            />
          </button>

        </div>

        <div className="api-panel">

          <div className="api-section-header">

            <div>
              <h2>
                Live Engine Activity
              </h2>

              <p>
                Current CalixAI execution
                state.
              </p>
            </div>

          </div>

          <div className="api-live-engine">

            {activeScans.length ===
            0 ? (
              <div className="api-engine-empty">

                <CheckCircle2
                  size={32}
                />

                <strong>
                  No active assessment
                </strong>

                <span>
                  Start a scan to see
                  live CalixAI engine
                  activity here.
                </span>

              </div>
            ) : (
              activeScans.map(
                (scan) => {
                  const live =
                    liveStatuses[
                      scan.scan_id
                    ];

                  return (
                    <div
                      className="api-live-scan"
                      key={
                        scan.scan_id
                      }
                    >

                      <div className="api-live-scan-header">

                        <div>
                          <strong>
                            {
                              getAssessmentId(
                                scan.scan_id,
                              )
                            }
                          </strong>

                          <span>
                            {scan.target}
                          </span>
                        </div>

                        <ScanStatusBadge
                          status={
                            live?.status ??
                            scan.status
                          }
                        />

                      </div>

                      <div className="api-live-phase">

                        <span>
                          ACTIVE AGENT
                        </span>

                        <strong>
                          {live?.active_agent ??
                            "Initializing"}
                        </strong>

                      </div>

                      <div className="api-live-phase">

                        <span>
                          PHASE
                        </span>

                        <strong>
                          {live?.phase ??
                            "Initializing"}
                        </strong>

                      </div>

                      <div className="api-live-progress">

                        <div>
                          <span>
                            PROGRESS
                          </span>

                          <strong>
                            {live?.progress ??
                              scan.progress ??
                              0}
                            %
                          </strong>
                        </div>

                        <div className="api-progress">

                          <span
                            style={{
                              width: `${
                                live?.progress ??
                                scan.progress ??
                                0
                              }%`,
                            }}
                          />

                        </div>

                      </div>

                    </div>
                  );
                },
              )
            )}

          </div>

        </div>

      </section>

      {/* API SECURITY COVERAGE */}

      <section className="api-coverage-section">

        <div className="api-section-header">

          <div>
            <h2>
              API Security Coverage
            </h2>

            <p>
              Security coverage metrics
              will be connected to actual
              scan findings as findings
              analytics are expanded.
            </p>
          </div>

        </div>

        <div className="api-coverage-grid">

          <CoverageCard
            type="blue"
            icon={
              <ShieldCheck
                size={26}
              />
            }
            label="Authentication Coverage"
            metric="—"
            description="Calculated from API authentication findings"
          />

          <CoverageCard
            type="purple"
            icon={
              <Sparkles
                size={26}
              />
            }
            label="AI Validation"
            metric="—"
            description="Calculated from AI-assisted finding validation"
          />

          <CoverageCard
            type="orange"
            icon={
              <AlertTriangle
                size={26}
              />
            }
            label="High Risk APIs"
            metric="—"
            description="Calculated from high-risk API findings"
          />

          <CoverageCard
            type="green"
            icon={
              <CheckCircle2
                size={26}
              />
            }
            label="Remediation"
            metric="—"
            description="Calculated from remediation status"
          />

        </div>

      </section>

      {/* FINDING DETAILS / REPORT MODAL */}

      {selectedScanId !==
        null && (
        <ScanDetails
          scanId={
            selectedScanId
          }
          scanLabel={getAssessmentId(
            selectedScanId,
          )}
          target={
            scans.find(
              (scan) =>
                scan.scan_id ===
                selectedScanId,
            )?.target ??
            "Security Assessment"
          }
          onClose={() =>
            setSelectedScanId(
              null,
            )
          }
        />
      )}

    </main>
  );
}
