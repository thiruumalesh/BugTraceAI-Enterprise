import {
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import type {
  ChangeEvent,
  DragEvent,
} from "react";

import {
  AlertTriangle,
  Download,
  FileSearch,
  FileText,
  Loader2,
  RefreshCw,
  ShieldCheck,
  Smartphone,
  UploadCloud,
} from "lucide-react";

import "./Mast.css";

const API_BASE = "/bugtrace-api";
const ACTIVE_SCAN_KEY = "calix_mast_active_scan";

type ScanStatus =
  | "idle"
  | "uploading"
  | "queued"
  | "scanning"
  | "completed"
  | "failed";

type Assessment = {
  scan_hash: string;

  application: {
    app_name?: string;
    file_name?: string;
    app_type?: string;
    package_name?: string;
    version_name?: string;
    version_code?: string;
    min_sdk?: string;
    target_sdk?: string;
    max_sdk?: string;
    sha256?: string;
    size?: string;
    main_activity?: string;
  };

  security: {
    security_score?: number;
    average_cvss?: number | null;
    high?: number;
    warning?: number;
    info?: number;
    secure?: number;
    hotspot?: number;
  };

  findings: Array<{
    title: string;
    severity: string;
    description?: string;
    remediation?: string | null;
    section?: string;
  }>;

  permissions: {
    total: number;
    dangerous: number;
  };

  trackers: {
    detected: number;
    total_known: number;
  };

  domains: {
    total: number;
  };

  secrets: {
    count: number;
  };

  urls: {
    count: number;
  };

  statistics: {
    finding_count: number;
    dangerous_permission_count: number;
    tracker_count: number;
    domain_count: number;
    secret_count: number;
    url_count: number;
  };
};

type ScanStatusResponse = {
  scan_hash: string;
  status: ScanStatus;
  progress: number;
  message: string;
  filename?: string;
  app_type?: string;
};

type MobSFScan = {
  ANALYZER?: string;
  SCAN_TYPE?: string;
  FILE_NAME?: string;
  APP_NAME?: string;
  PACKAGE_NAME?: string;
  VERSION_NAME?: string;
  MD5?: string;
  TIMESTAMP?: string;
};

type ScanListResponse = {
  content?: MobSFScan[];
  count?: number;
  num_pages?: number;
};

function severityClass(severity: string) {
  const normalized = severity.toLowerCase();

  if (normalized === "high") return "high";
  if (normalized === "medium" || normalized === "warning") return "medium";
  if (normalized === "low") return "low";

  return "info";
}

function typeLabel(type?: string) {
  return String(type || "").toLowerCase() === "ipa"
    ? "IPA"
    : "APK";
}

function formatDate(value?: string) {
  if (!value) return "-";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) return value;

  return date.toLocaleString();
}

function riskLabel(score?: number) {
  if (score === undefined || score === null) return "Pending";

  if (score < 40) return "Critical Risk";
  if (score < 60) return "High Risk";
  if (score < 80) return "Medium Risk";

  return "Low Risk";
}

export default function Mast() {
  const [assessment, setAssessment] =
    useState<Assessment | null>(null);

  const [completedScans, setCompletedScans] =
    useState<MobSFScan[]>([]);

  const [completedAssessments, setCompletedAssessments] =
    useState<Record<string, Assessment>>({});

  const [scanHash, setScanHash] =
    useState("");

  const [scanStatus, setScanStatus] =
    useState<ScanStatus>("idle");

  const [progress, setProgress] =
    useState(0);

  const [statusMessage, setStatusMessage] =
    useState(
      "Upload an Android APK or iOS IPA to begin."
    );

  const [selectedFile, setSelectedFile] =
    useState<File | null>(null);

  const [dragActive, setDragActive] =
    useState(false);

  const [loadingAssessment, setLoadingAssessment] =
    useState(false);

  const [loadingScans, setLoadingScans] =
    useState(false);

  const [error, setError] =
    useState("");

  const inputRef =
    useRef<HTMLInputElement | null>(null);

  const pollTimer =
    useRef<number | null>(null);

  const refreshTimer =
    useRef<number | null>(null);

  const stopPolling = useCallback(() => {
    if (pollTimer.current !== null) {
      window.clearTimeout(pollTimer.current);
      pollTimer.current = null;
    }
  }, []);

  const stopRefresh = useCallback(() => {
    if (refreshTimer.current !== null) {
      window.clearInterval(refreshTimer.current);
      refreshTimer.current = null;
    }
  }, []);

  const loadAssessment = useCallback(
    async (hash: string) => {
      try {
        setLoadingAssessment(true);
        setError("");

        const response = await fetch(
          `${API_BASE}/api/mast/scans/${hash}`
        );

        if (!response.ok) {
          throw new Error(
            `Unable to load MAST assessment: HTTP ${response.status}`
          );
        }

        const data =
          (await response.json()) as Assessment;

        setAssessment(data);
        setScanHash(hash);
        setScanStatus("completed");
        setProgress(100);

        setCompletedAssessments((previous) => ({
          ...previous,
          [hash]: data,
        }));
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Unable to load MAST assessment."
        );
      } finally {
        setLoadingAssessment(false);
      }
    },
    []
  );

  const loadRecentScans = useCallback(
    async () => {
      try {
        setLoadingScans(true);

        const response = await fetch(
          `${API_BASE}/api/mast/scans`
        );

        if (!response.ok) {
          throw new Error(
            `Unable to retrieve MAST scans: HTTP ${response.status}`
          );
        }

        const data =
          (await response.json()) as ScanListResponse;

        const scans =
          Array.isArray(data.content)
            ? data.content
            : [];

        setCompletedScans(scans);

        /*
         * Load normalized assessments for recent scans.
         * Limited to the latest 10 so the dashboard remains responsive.
         */
        const latest = scans.slice(0, 10);

        const results =
          await Promise.allSettled(
            latest
              .filter((scan) => scan.MD5)
              .map(async (scan) => {
                const hash = scan.MD5 as string;

                const response = await fetch(
                  `${API_BASE}/api/mast/scans/${hash}`
                );

                if (!response.ok) {
                  throw new Error(
                    `Assessment failed for ${hash}`
                  );
                }

                return (await response.json()) as Assessment;
              })
          );

        const assessmentMap: Record<string, Assessment> = {};

        for (const result of results) {
          if (result.status === "fulfilled") {
            assessmentMap[result.value.scan_hash] =
              result.value;
          }
        }

        setCompletedAssessments((previous) => ({
          ...previous,
          ...assessmentMap,
        }));
      } catch (err) {
        console.error(
          "MAST recent scans error:",
          err
        );
      } finally {
        setLoadingScans(false);
      }
    },
    []
  );

  const pollStatus = useCallback(
    async (hash: string) => {
      try {
        const response = await fetch(
          `${API_BASE}/api/mast/scans/${hash}/status`
        );

        if (!response.ok) {
          throw new Error(
            `MAST status API returned HTTP ${response.status}`
          );
        }

        const data =
          (await response.json()) as ScanStatusResponse;

        const currentProgress = Math.min(
          100,
          Math.max(0, Number(data.progress) || 0)
        );

        setProgress(currentProgress);
        setStatusMessage(
          data.message || "Scanning mobile application..."
        );
        setScanStatus(data.status);

        if (data.status === "completed") {
          stopPolling();

          localStorage.removeItem(
            ACTIVE_SCAN_KEY
          );

          await loadAssessment(hash);
          await loadRecentScans();

          return;
        }

        if (data.status === "failed") {
          stopPolling();

          localStorage.removeItem(
            ACTIVE_SCAN_KEY
          );

          setError(
            data.message ||
              "MobSF scan failed."
          );

          await loadRecentScans();

          return;
        }

        pollTimer.current =
          window.setTimeout(() => {
            void pollStatus(hash);
          }, 2500);
      } catch (err) {
        stopPolling();

        setScanStatus("failed");

        setError(
          err instanceof Error
            ? err.message
            : "Unable to retrieve MAST scan status."
        );
      }
    },
    [
      loadAssessment,
      loadRecentScans,
      stopPolling,
    ]
  );

  const restoreActiveScan = useCallback(
    async () => {
      const stored =
        localStorage.getItem(
          ACTIVE_SCAN_KEY
        );

      if (!stored) return;

      try {
        const saved =
          JSON.parse(stored) as {
            scan_hash?: string;
            filename?: string;
            app_type?: string;
          };

        if (!saved.scan_hash) {
          localStorage.removeItem(
            ACTIVE_SCAN_KEY
          );
          return;
        }

        setScanHash(saved.scan_hash);
        setScanStatus("scanning");
        setProgress(25);
        setStatusMessage(
          "Restoring MAST scan status..."
        );

        await pollStatus(
          saved.scan_hash
        );
      } catch {
        localStorage.removeItem(
          ACTIVE_SCAN_KEY
        );
      }
    },
    [pollStatus]
  );

  useEffect(() => {
    void loadRecentScans();
    void restoreActiveScan();

    refreshTimer.current =
      window.setInterval(() => {
        void loadRecentScans();
      }, 10000);

    return () => {
      stopPolling();
      stopRefresh();
    };
  }, [
    loadRecentScans,
    restoreActiveScan,
    stopPolling,
    stopRefresh,
  ]);

  const uploadFile = async (file: File) => {
    const extension =
      file.name
        .split(".")
        .pop()
        ?.toLowerCase();

    if (
      extension !== "apk" &&
      extension !== "ipa"
    ) {
      setError(
        "Invalid file. Please select an APK or IPA file."
      );
      return;
    }

    stopPolling();

    setError("");
    setAssessment(null);
    setSelectedFile(file);
    setScanHash("");
    setProgress(5);
    setScanStatus("uploading");
    setStatusMessage(
      "Uploading application to MobSF..."
    );

    try {
      const formData =
        new FormData();

      formData.append(
        "file",
        file
      );

      const response = await fetch(
        `${API_BASE}/api/mast/upload`,
        {
          method: "POST",
          body: formData,
        }
      );

      if (!response.ok) {
        let message =
          `Upload failed: HTTP ${response.status}`;

        try {
          const body =
            await response.json();

          if (body?.detail) {
            message = body.detail;
          }
        } catch {
          // Keep default error.
        }

        throw new Error(message);
      }

      const data =
        await response.json();

      const hash =
        data.scan_hash;

      if (!hash) {
        throw new Error(
          "Upload succeeded but MAST API did not return a scan hash."
        );
      }

      localStorage.setItem(
        ACTIVE_SCAN_KEY,
        JSON.stringify({
          scan_hash: hash,
          filename: file.name,
          app_type: extension,
        })
      );

      setScanHash(hash);
      setProgress(10);
      setScanStatus("queued");
      setStatusMessage(
        "File uploaded successfully. MobSF scan queued..."
      );

      void pollStatus(hash);
    } catch (err) {
      setScanStatus("failed");

      setError(
        err instanceof Error
          ? err.message
          : "Unable to upload application."
      );
    }
  };

  const handleFileChange = (
    event: ChangeEvent<HTMLInputElement>
  ) => {
    const file =
      event.target.files?.[0];

    if (file) {
      void uploadFile(file);
    }

    event.target.value = "";
  };

  const handleDrop = (
    event: DragEvent<HTMLDivElement>
  ) => {
    event.preventDefault();
    event.stopPropagation();

    setDragActive(false);

    const file =
      event.dataTransfer.files?.[0];

    if (file) {
      void uploadFile(file);
    }
  };

  const handleDragOver = (
    event: DragEvent<HTMLDivElement>
  ) => {
    event.preventDefault();
    event.stopPropagation();

    setDragActive(true);
  };

  const handleDragLeave = (
    event: DragEvent<HTMLDivElement>
  ) => {
    event.preventDefault();
    event.stopPropagation();

    setDragActive(false);
  };

  const chooseFile = () => {
    inputRef.current?.click();
  };

  const newScan = () => {
    stopPolling();

    localStorage.removeItem(
      ACTIVE_SCAN_KEY
    );

    setAssessment(null);
    setSelectedFile(null);
    setScanHash("");
    setScanStatus("idle");
    setProgress(0);
    setError("");
    setStatusMessage(
      "Upload an Android APK or iOS IPA to begin."
    );
  };

  const viewAssessment = async (
    hash: string
  ) => {
    await loadAssessment(hash);

    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  };

  const downloadReport = async (
    hash: string,
    format: "pdf" | "json",
    filename?: string
  ) => {
    try {
      const response = await fetch(
        `${API_BASE}/api/mast/scans/${hash}/report/${format}`
      );

      if (!response.ok) {
        throw new Error(
          `Unable to download ${format.toUpperCase()} report: HTTP ${response.status}`
        );
      }

      const blob =
        await response.blob();

      const url =
        window.URL.createObjectURL(
          blob
        );

      const link =
        document.createElement("a");

      link.href = url;

      const rawName =
        filename ||
        "MAST_Report";

      const baseName =
        rawName.replace(
          /\.(apk|ipa)$/i,
          ""
        );

      link.download =
        format === "pdf"
          ? `Calix_MAST_${baseName}.pdf`
          : `Calix_MAST_${baseName}.json`;

      document.body.appendChild(
        link
      );

      link.click();
      link.remove();

      window.URL.revokeObjectURL(
        url
      );
    } catch (err) {
      window.alert(
        err instanceof Error
          ? err.message
          : "Unable to download MAST report."
      );
    }
  };

  const showProgress =
    !assessment &&
    (
      scanStatus === "uploading" ||
      scanStatus === "queued" ||
      scanStatus === "scanning"
    );

  const activeScan =
    scanHash && showProgress
      ? {
          hash: scanHash,
          filename:
            selectedFile?.name ||
            "Mobile application",
          appType:
            selectedFile?.name
              ?.split(".")
              .pop()
              ?.toUpperCase() ||
            "APP",
        }
      : null;

  if (loadingAssessment) {
    return (
      <div className="mast-state">
        <Loader2
          className="mast-spinner"
          size={34}
        />
        <span>
          Loading mobile security assessment...
        </span>
      </div>
    );
  }

  if (assessment) {
    const score =
      assessment.security.security_score ?? 0;

    return (
      <div className="mast-page">
        <section className="mast-intro">
          <div>
            <div className="mast-eyebrow">
              MOBILE APPLICATION SECURITY
            </div>

            <h2>
              MAST Assessment
            </h2>

            <p>
              Android and iOS application security
              testing powered by MobSF and CalixAI.
            </p>
          </div>

          <div className="mast-header-actions">
            <button
              className="mast-download-button"
              onClick={() =>
                void downloadReport(
                  assessment.scan_hash,
                  "pdf",
                  assessment.application.file_name
                )
              }
            >
              <FileText size={17} />
              Download Calix MAST PDF
            </button>

            <button
              className="mast-download-button"
              onClick={() =>
                void downloadReport(
                  assessment.scan_hash,
                  "json",
                  assessment.application.file_name
                )
              }
            >
              <Download size={17} />
              Download JSON
            </button>

            <button
              className="mast-new-scan-button"
              onClick={newScan}
            >
              <RefreshCw size={17} />
              New Scan
            </button>

            <div className="mast-engine">
              <span />
              MOBSF ENGINE ONLINE
            </div>
          </div>
        </section>

        {error && (
          <div className="mast-error-banner">
            <AlertTriangle size={20} />

            <div>
              <strong>
                MAST Scan Error
              </strong>

              <p>{error}</p>
            </div>

            <button
              onClick={() =>
                setError("")
              }
            >
              Dismiss
            </button>
          </div>
        )}

        <section className="mast-application-card">
          <div className="mast-app-icon">
            <Smartphone size={28} />
          </div>

          <div>
            <span>APPLICATION</span>
            <strong>
              {assessment.application.app_name ||
                "Mobile Application"}
            </strong>
            <small>
              {assessment.application.package_name ||
                "iOS / Android"}
            </small>
          </div>

          <div>
            <span>TYPE</span>
            <strong>
              {typeLabel(
                assessment.application.app_type
              )}
            </strong>
          </div>

          <div>
            <span>FILE</span>
            <strong>
              {assessment.application.file_name ||
                "-"}
            </strong>
          </div>

          <div>
            <span>SHA-256</span>
            <strong className="mast-hash">
              {assessment.application.sha256 ||
                "-"}
            </strong>
          </div>
        </section>

        <section className="mast-summary-grid">
          <div className="mast-score-card">
            <div className="mast-score-circle">
              {score}
              <small>/100</small>
            </div>

            <div>
              <span>
                SECURITY SCORE
              </span>

              <strong>
                {riskLabel(score)}
              </strong>
            </div>
          </div>

          <div className="mast-stat high">
            <span>HIGH</span>
            <strong>
              {assessment.security.high ?? 0}
            </strong>
          </div>

          <div className="mast-stat medium">
            <span>MEDIUM</span>
            <strong>
              {assessment.security.warning ?? 0}
            </strong>
          </div>

          <div className="mast-stat info">
            <span>INFO</span>
            <strong>
              {assessment.security.info ?? 0}
            </strong>
          </div>
        </section>

        <section className="mast-mini-grid">
          <div>
            <ShieldCheck size={20} />
            <span>DANGEROUS PERMISSIONS</span>
            <strong>
              {assessment.permissions.dangerous}
            </strong>
          </div>

          <div>
            <FileSearch size={20} />
            <span>SECRETS DETECTED</span>
            <strong>
              {assessment.secrets.count}
            </strong>
          </div>

          <div>
            <AlertTriangle size={20} />
            <span>TRACKERS</span>
            <strong>
              {assessment.trackers.detected}
            </strong>
          </div>

          <div>
            <FileSearch size={20} />
            <span>DOMAINS</span>
            <strong>
              {assessment.domains.total}
            </strong>
          </div>
        </section>

        <section className="mast-findings-section">
          <div className="mast-section-header">
            <div>
              <span>
                SECURITY ANALYSIS
              </span>
              <h3>
                Findings
              </h3>
            </div>

            <strong>
              {assessment.findings.length} findings
            </strong>
          </div>

          {assessment.findings.map(
            (finding, index) => (
              <article
                className="mast-finding"
                key={`${finding.title}-${index}`}
              >
                <div
                  className={`mast-severity ${severityClass(
                    finding.severity
                  )}`}
                >
                  {finding.severity}
                </div>

                <div className="mast-finding-body">
                  <h4>
                    {finding.title}
                  </h4>

                  {finding.description && (
                    <p>
                      {finding.description}
                    </p>
                  )}

                  {finding.remediation && (
                    <div className="mast-remediation">
                      <strong>
                        Remediation:
                      </strong>{" "}
                      {finding.remediation}
                    </div>
                  )}

                  {finding.section && (
                    <small>
                      Section: {finding.section}
                    </small>
                  )}
                </div>
              </article>
            )
          )}
        </section>
      </div>
    );
  }

  return (
    <div className="mast-page">
      <section className="mast-intro">
        <div>
          <div className="mast-eyebrow">
            MOBILE APPLICATION SECURITY
          </div>

          <h2>
            MAST Security Dashboard
          </h2>

          <p>
            Android and iOS application security
            testing powered by MobSF and CalixAI.
          </p>
        </div>

        <div className="mast-header-actions">
          <button
            className="mast-refresh-button"
            onClick={() =>
              void loadRecentScans()
            }
          >
            <RefreshCw size={16} />
            Refresh
          </button>

          <div className="mast-engine">
            <span />
            MOBSF ENGINE ONLINE
          </div>
        </div>
      </section>

      {error && (
        <div className="mast-error-banner">
          <AlertTriangle size={20} />

          <div>
            <strong>
              MAST Scan Error
            </strong>

            <p>{error}</p>
          </div>

          <button
            onClick={() =>
              setError("")
            }
          >
            Dismiss
          </button>
        </div>
      )}

      <section className="mast-dashboard-summary">
        <div>
          <span>ACTIVE SCAN</span>
          <strong>
            {activeScan ? "1" : "0"}
          </strong>
        </div>

        <div>
          <span>COMPLETED</span>
          <strong>
            {completedScans.length}
          </strong>
        </div>

        <div>
          <span>APK</span>
          <strong>
            {
              completedScans.filter(
                (scan) =>
                  String(scan.SCAN_TYPE)
                    .toLowerCase() === "apk"
              ).length
            }
          </strong>
        </div>

        <div>
          <span>IPA</span>
          <strong>
            {
              completedScans.filter(
                (scan) =>
                  String(scan.SCAN_TYPE)
                    .toLowerCase() === "ipa"
              ).length
            }
          </strong>
        </div>
      </section>

      {activeScan && (
        <section className="mast-active-card">
          <div className="mast-active-top">
            <div className="mast-progress-file">
              <div className="mast-progress-file-icon">
                <Smartphone size={25} />
              </div>

              <div>
                <span>
                  MOBILE APPLICATION
                </span>

                <strong>
                  {activeScan.filename}
                </strong>
              </div>
            </div>

            <div className="mast-running">
              <Loader2
                size={17}
                className="mast-spinner"
              />
              {statusMessage}
            </div>
          </div>

          <div className="mast-active-body">
            <div className="mast-progress-title">
              <div>
                <span>
                  MAST SCAN
                </span>

                <h3>
                  {statusMessage}
                </h3>
              </div>

              <strong>
                {progress}%
              </strong>
            </div>

            <div className="mast-progress-track">
              <div
                className="mast-progress-bar"
                style={{
                  width: `${progress}%`,
                }}
              />
            </div>

            <div className="mast-stage-row">
              <div
                className={
                  progress >= 5
                    ? "active"
                    : ""
                }
              >
                <span>1</span>
                Upload
              </div>

              <div
                className={
                  progress >= 20
                    ? "active"
                    : ""
                }
              >
                <span>2</span>
                Initialize
              </div>

              <div
                className={
                  progress >= 40
                    ? "active"
                    : ""
                }
              >
                <span>3</span>
                Static Analysis
              </div>

              <div
                className={
                  progress >= 80
                    ? "active"
                    : ""
                }
              >
                <span>4</span>
                Security Analysis
              </div>

              <div
                className={
                  progress >= 100
                    ? "active"
                    : ""
                }
              >
                <span>5</span>
                Complete
              </div>
            </div>

            <div className="mast-active-message">
              <Loader2
                size={16}
                className="mast-spinner"
              />
              MobSF is analyzing the application.
              Please keep this page open.
            </div>
          </div>
        </section>
      )}

      <section className="mast-upload-section">
        <div className="mast-upload-header">
          <div>
            <span>
              MOBILE APPLICATION SECURITY TESTING
            </span>

            <h3>
              Upload Application
            </h3>

            <p>
              Upload an Android APK or iOS IPA
              directly from this dashboard.
            </p>
          </div>
        </div>

        <div
          className={`mast-dropzone ${
            dragActive
              ? "drag-active"
              : ""
          }`}
          onClick={chooseFile}
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
        >
          <div className="mast-upload-icon">
            <UploadCloud size={38} />
          </div>

          <h3>
            Drop APK or IPA here
          </h3>

          <p>
            or click to browse your files
          </p>

          <button
            type="button"
            className="mast-browse-button"
            onClick={(event) => {
              event.stopPropagation();
              chooseFile();
            }}
          >
            Browse Files
          </button>

          <div className="mast-upload-hint">
            Supported formats: APK, IPA
          </div>

          <input
            ref={inputRef}
            type="file"
            accept=".apk,.ipa"
            hidden
            onChange={handleFileChange}
          />
        </div>
      </section>

      <section className="mast-completed-section">
        <div className="mast-section-header">
          <div>
            <span>
              MAST SCAN HISTORY
            </span>

            <h3>
              Completed Applications
            </h3>
          </div>

          <strong>
            {completedScans.length} scans
          </strong>
        </div>

        {loadingScans &&
          completedScans.length === 0 && (
            <div className="mast-history-loading">
              <Loader2
                size={20}
                className="mast-spinner"
              />
              Loading completed scans...
            </div>
          )}

        {!loadingScans &&
          completedScans.length === 0 && (
            <div className="mast-empty">
              <FileSearch size={34} />
              <strong>
                No completed MAST scans
              </strong>
              <span>
                Upload an APK or IPA to start your
                first mobile security assessment.
              </span>
            </div>
          )}

        {completedScans.map(
          (scan, index) => {
            const hash =
              scan.MD5 || "";

            const itemAssessment =
              completedAssessments[hash];

            const score =
              itemAssessment?.security
                ?.security_score;

            const high =
              itemAssessment?.security?.high;

            const medium =
              itemAssessment?.security?.warning;

            const info =
              itemAssessment?.security?.info;

            return (
              <article
                className="mast-history-row"
                key={
                  hash ||
                  `${scan.FILE_NAME}-${index}`
                }
              >
                <div className="mast-history-app">
                  <div className="mast-history-icon">
                    <Smartphone size={21} />
                  </div>

                  <div>
                    <strong>
                      {scan.APP_NAME ||
                        "Mobile Application"}
                    </strong>

                    <span>
                      {scan.PACKAGE_NAME ||
                        scan.FILE_NAME ||
                        "-"}
                    </span>
                  </div>
                </div>

                <div className="mast-history-file">
                  <span>FILE</span>
                  <strong>
                    {scan.FILE_NAME || "-"}
                  </strong>
                </div>

                <div className="mast-history-type">
                  <span>TYPE</span>
                  <strong>
                    {typeLabel(
                      scan.SCAN_TYPE
                    )}
                  </strong>
                </div>

                <div className="mast-history-score">
                  <span>SCORE</span>
                  <strong>
                    {score !== undefined
                      ? `${score}/100`
                      : "—"}
                  </strong>
                </div>

                <div className="mast-history-severity">
                  <span>FINDINGS</span>

                  <div>
                    <b className="h">
                      H {high ?? "—"}
                    </b>

                    <b className="m">
                      M {medium ?? "—"}
                    </b>

                    <b className="i">
                      I {info ?? "—"}
                    </b>
                  </div>
                </div>

                <div className="mast-history-date">
                  <span>COMPLETED</span>
                  <strong>
                    {formatDate(
                      scan.TIMESTAMP
                    )}
                  </strong>
                </div>

                <div className="mast-history-actions">
                  {hash && (
                    <>
                      <button
                        onClick={() =>
                          void viewAssessment(
                            hash
                          )
                        }
                        title="View vulnerabilities"
                      >
                        <FileSearch
                          size={15}
                        />
                        View
                      </button>

                      <button
                        onClick={() =>
                          void downloadReport(
                            hash,
                            "pdf",
                            scan.FILE_NAME
                          )
                        }
                        title="Download Calix MAST PDF"
                      >
                        <FileText
                          size={15}
                        />
                        PDF
                      </button>

                      <button
                        onClick={() =>
                          void downloadReport(
                            hash,
                            "json",
                            scan.FILE_NAME
                          )
                        }
                        title="Download JSON"
                      >
                        <Download
                          size={15}
                        />
                        JSON
                      </button>
                    </>
                  )}
                </div>
              </article>
            );
          }
        )}
      </section>
    </div>
  );
}
