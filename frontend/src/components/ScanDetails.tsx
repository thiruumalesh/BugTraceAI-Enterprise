import {
  AlertTriangle,
  CheckCircle2,
  Download,
  FileText,
  X,
} from "lucide-react";
import { useEffect, useState } from "react";
import jsPDF from "jspdf";

import {
  getReportUrl,
  getReportZipUrl,
  getScanFindings,
  type ScanFinding,
} from "../services/bugtraceApi";

import "./ScanDetails.css";

interface ScanDetailsProps {
  scanId: number | null;
  scanLabel: string;
  target: string;
  onClose: () => void;
}

function severityClass(severity: string) {
  return severity.toLowerCase().replace(/[^a-z]/g, "");
}

function formatConfidence(value: number) {
  if (value <= 1) {
    return `${Math.round(value * 100)}%`;
  }

  return `${Math.round(value)}%`;
}

function safeText(value: unknown) {
  if (value === null || value === undefined) {
    return "";
  }

  if (typeof value === "string") {
    return value;
  }

  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}


/* =========================================================
   CALIXAI REMEDIATION ENGINE
   ========================================================= */

interface RemediationGuidance {
  summary: string;
  actions: string[];
}

function getCalixAIRemediation(
  finding: ScanFinding,
): RemediationGuidance {
  const type = String(
    finding.type || "",
  ).toLowerCase();

  const details = safeText(
    finding.details,
  ).toLowerCase();

  const parameter = String(
    finding.parameter || "",
  ).toLowerCase();

  /*
   * Cross-Site Scripting
   */
  if (
    type.includes("xss") ||
    type.includes("cross-site scripting")
  ) {
    return {
      summary:
        "Prevent untrusted input from being interpreted as executable browser content.",
      actions: [
        "Apply context-aware output encoding before rendering untrusted data.",
        "Validate and constrain untrusted input on the server side.",
        "Avoid unsafe DOM APIs such as innerHTML when safer alternatives are available.",
        "Use a restrictive Content-Security-Policy as an additional defense layer.",
        "Add automated regression tests for reflected, stored, and DOM-based XSS.",
      ],
    };
  }

  /*
   * Broken Access Control
   */
  if (
    type.includes("broken access control") ||
    type.includes("access control") ||
    type.includes("authorization")
  ) {
    return {
      summary:
        "Enforce authorization on the server for every protected resource and administrative action.",
      actions: [
        "Validate authorization server-side on every protected endpoint.",
        "Verify the authenticated user's role and permissions before returning protected resources.",
        "Do not rely on client-side access controls for security enforcement.",
        "Test both horizontal and vertical privilege escalation scenarios.",
        "Add authorization regression tests for administrative and sensitive endpoints.",
      ],
    };
  }

  /*
   * Rate Limiting
   */
  if (
    type.includes("rate limiting") ||
    type.includes("rate-limit") ||
    type.includes("no-rate-limiting") ||
    parameter.includes("rate")
  ) {
    return {
      summary:
        "Apply server-side rate limiting and abuse protection to sensitive endpoints.",
      actions: [
        "Implement server-side request throttling for sensitive endpoints.",
        "Apply stricter controls to authentication and login operations.",
        "Use appropriate per-user, per-IP, token, or account-based limits.",
        "Return appropriate rate-limit responses such as HTTP 429.",
        "Monitor repeated failures and suspicious request patterns.",
      ],
    };
  }

  /*
   * Security Headers
   */
  if (
    type.includes("missing_security_header") ||
    type.includes("missing security header") ||
    type.includes("security header")
  ) {
    if (
      details.includes("content-security-policy") ||
      parameter.includes("csp")
    ) {
      return {
        summary:
          "Define and enforce a restrictive Content-Security-Policy appropriate for the application.",
        actions: [
          "Configure the Content-Security-Policy HTTP response header.",
          "Start with a report-only policy when validating application compatibility.",
          "Restrict script, object, frame, image, and connection sources as appropriate.",
          "Remove unnecessary unsafe-inline and unsafe-eval usage where possible.",
          "Continuously review CSP violations and update the policy safely.",
        ],
      };
    }

    if (
      details.includes("hsts") ||
      parameter.includes("hsts")
    ) {
      return {
        summary:
          "Enable HTTP Strict Transport Security for HTTPS-protected application traffic.",
        actions: [
          "Return the Strict-Transport-Security response header over HTTPS.",
          "Configure an appropriate max-age value.",
          "Consider includeSubDomains after validating all affected subdomains.",
          "Ensure the application does not depend on insecure HTTP access.",
          "Validate the configuration before enabling preload-related settings.",
        ],
      };
    }

    if (
      details.includes("x-content-type-options") ||
      parameter.includes("xxp")
    ) {
      return {
        summary:
          "Prevent browsers from MIME-sniffing responses where the application does not explicitly permit it.",
        actions: [
          "Return X-Content-Type-Options: nosniff.",
          "Configure the header consistently across application responses.",
          "Verify static assets and API responses after enabling the header.",
        ],
      };
    }

    if (
      details.includes("referrer-policy") ||
      parameter.includes("rp")
    ) {
      return {
        summary:
          "Configure an appropriate Referrer-Policy to control referrer information sent by the browser.",
        actions: [
          "Return an explicit Referrer-Policy response header.",
          "Use a restrictive policy appropriate for the application's data sensitivity.",
          "Validate navigation and third-party integration requirements.",
        ],
      };
    }

    if (
      details.includes("permissions-policy") ||
      parameter.includes("pp")
    ) {
      return {
        summary:
          "Restrict browser capabilities that are not required by the application.",
        actions: [
          "Configure an explicit Permissions-Policy response header.",
          "Disable unused browser features.",
          "Review required browser capabilities before enforcing the policy.",
        ],
      };
    }

    return {
      summary:
        "Configure appropriate HTTP security headers according to the application's security requirements.",
      actions: [
        "Review the missing HTTP security header identified by the assessment.",
        "Configure the header at the application, reverse proxy, or web server layer.",
        "Apply the configuration consistently across relevant responses.",
        "Validate the resulting headers using automated security tests.",
      ],
    };
  }

  /*
   * Generic fallback
   */
  return {
    summary:
      "Review and remediate the identified security weakness according to the affected component and security requirements.",
    actions: [
      "Review the affected endpoint and determine the underlying security control gap.",
      "Apply a server-side security control appropriate to the vulnerability.",
      "Add automated regression coverage for the affected security control.",
      "Re-run the CalixAI security assessment after remediation.",
      "Verify that the finding is no longer reproducible.",
    ],
  };
}

/* =========================================================
   CALIXAI LOCAL PDF REPORT
   ========================================================= */

function generateCalixAIPdf(
  scanId: number,
  scanLabel: string,
  target: string,
  findings: ScanFinding[],
) {
  const doc = new jsPDF({
    orientation: "portrait",
    unit: "mm",
    format: "a4",
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();

  const margin = 16;
  const contentWidth = pageWidth - margin * 2;

  let y = 20;

  function addHeader() {
    doc.setFillColor(12, 99, 190);
    doc.rect(0, 0, pageWidth, 28, "F");

    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.text("CALIXAI", margin, 12);

    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.text(
      "SECURITY TESTING PLATFORM",
      margin,
      19,
    );

    doc.setFont("helvetica", "bold");
    doc.setFontSize(10);
    doc.text(
      "API / DAST SECURITY TESTING REPORT",
      pageWidth - margin,
      16,
      {
        align: "right",
      },
    );

    y = 38;
  }

  function addFooter() {
    const pageNumber = doc.getNumberOfPages();

    doc.setDrawColor(220, 228, 236);
    doc.line(
      margin,
      pageHeight - 14,
      pageWidth - margin,
      pageHeight - 14,
    );

    doc.setTextColor(100, 120, 140);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);

    doc.text(
      "CalixAI Security Testing Report",
      margin,
      pageHeight - 8,
    );

    doc.text(
      `Page ${pageNumber}`,
      pageWidth - margin,
      pageHeight - 8,
      {
        align: "right",
      },
    );
  }

  function ensureSpace(requiredHeight: number) {
    if (y + requiredHeight > pageHeight - 22) {
      addFooter();
      doc.addPage();
      addHeader();
    }
  }

  function addSectionTitle(title: string) {
    ensureSpace(16);

    doc.setFillColor(235, 244, 252);
    doc.roundedRect(
      margin,
      y - 5,
      contentWidth,
      10,
      2,
      2,
      "F",
    );

    doc.setTextColor(18, 66, 108);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.text(title, margin + 4, y + 1);

    y += 14;
  }

  function addLabelValue(
    label: string,
    value: string,
  ) {
    ensureSpace(12);

    doc.setTextColor(85, 105, 125);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8);
    doc.text(label, margin, y);

    doc.setTextColor(25, 55, 85);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);

    const wrapped = doc.splitTextToSize(
      value || "N/A",
      contentWidth - 38,
    );

    doc.text(
      wrapped,
      margin + 38,
      y,
    );

    y += Math.max(6, wrapped.length * 4.5);
  }

  function addWrappedText(
    text: string,
    fontSize = 8.5,
  ) {
    const normalized = safeText(text) || "N/A";

    doc.setFont("helvetica", "normal");
    doc.setFontSize(fontSize);
    doc.setTextColor(45, 65, 85);

    const wrapped = doc.splitTextToSize(
      normalized,
      contentWidth,
    );

    const requiredHeight =
      Math.max(1, wrapped.length) * 4.5 + 5;

    ensureSpace(requiredHeight);

    doc.text(wrapped, margin, y);

    y += requiredHeight;
  }

  function addFinding(
    finding: ScanFinding,
    index: number,
  ) {
    ensureSpace(45);

    const severity =
      String(finding.severity || "INFO").toUpperCase();

    const severityColor =
      severity === "CRITICAL"
        ? [190, 35, 35]
        : severity === "HIGH"
          ? [220, 115, 15]
          : severity === "MEDIUM"
            ? [210, 160, 0]
            : severity === "LOW"
              ? [0, 145, 105]
              : [90, 110, 130];

    doc.setDrawColor(215, 225, 235);
    doc.setFillColor(249, 251, 253);

    doc.roundedRect(
      margin,
      y,
      contentWidth,
      10,
      2,
      2,
      "FD",
    );

    doc.setTextColor(20, 60, 95);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(9);

    doc.text(
      `Finding #${index + 1}`,
      margin + 4,
      y + 6.5,
    );

    doc.setTextColor(
      severityColor[0],
      severityColor[1],
      severityColor[2],
    );

    doc.text(
      severity,
      pageWidth - margin - 4,
      y + 6.5,
      {
        align: "right",
      },
    );

    y += 15;

    addLabelValue(
      "Finding ID",
      String(finding.finding_id ?? "N/A"),
    );

    addLabelValue(
      "Type",
      String(finding.type || "N/A"),
    );

    addLabelValue(
      "URL",
      String(finding.url || "N/A"),
    );

    addLabelValue(
      "Parameter",
      String(finding.parameter || "N/A"),
    );

    addLabelValue(
      "Validation",
      finding.validated
        ? "Confirmed"
        : "Not Confirmed",
    );

    addLabelValue(
      "Status",
      String(finding.status || "N/A"),
    );

    addLabelValue(
      "Confidence",
      formatConfidence(
        Number(finding.confidence || 0),
      ),
    );

    ensureSpace(15);

    doc.setTextColor(70, 95, 120);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8);
    doc.text("Details", margin, y);

    y += 5;

    doc.setFillColor(247, 250, 252);
    doc.setDrawColor(220, 228, 236);

    const details = safeText(
      finding.details,
    ) || "No additional details available.";

    const detailLines = doc.splitTextToSize(
      details,
      contentWidth - 8,
    );

    const detailHeight =
      Math.max(12, detailLines.length * 4.2 + 8);

    ensureSpace(detailHeight + 4);

    doc.roundedRect(
      margin,
      y,
      contentWidth,
      detailHeight,
      2,
      2,
      "FD",
    );

    doc.setFont("courier", "normal");
    doc.setFontSize(7.5);
    doc.setTextColor(45, 65, 85);

    doc.text(
      detailLines,
      margin + 4,
      y + 6,
    );

    y += detailHeight + 6;

    doc.setFont("helvetica", "bold");
    doc.setFontSize(8);
    doc.setTextColor(70, 95, 120);

    doc.text(
      "Payload / Evidence",
      margin,
      y,
    );

    y += 5;

    const payload =
      safeText(finding.payload) ||
      "No payload or evidence recorded.";

    const payloadLines = doc.splitTextToSize(
      payload,
      contentWidth - 8,
    );

    const payloadHeight =
      Math.max(12, payloadLines.length * 4.2 + 8);

    ensureSpace(payloadHeight + 4);

    doc.setFillColor(247, 250, 252);
    doc.setDrawColor(220, 228, 236);

    doc.roundedRect(
      margin,
      y,
      contentWidth,
      payloadHeight,
      2,
      2,
      "FD",
    );

    doc.setFont("courier", "normal");
    doc.setFontSize(7.5);
    doc.setTextColor(45, 65, 85);

    doc.text(
      payloadLines,
      margin + 4,
      y + 6,
    );

    y += payloadHeight + 10;

    /*
     * Remediation
     */
    const remediation =
      getCalixAIRemediation(finding);

    ensureSpace(20);

    doc.setFillColor(236, 248, 241);
    doc.setDrawColor(190, 225, 204);

    doc.roundedRect(
      margin,
      y,
      contentWidth,
      11,
      2,
      2,
      "FD",
    );

    doc.setTextColor(25, 105, 65);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(9);

    doc.text(
      "REMEDIATION",
      margin + 4,
      y + 7,
    );

    y += 16;

    doc.setTextColor(35, 65, 55);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8.5);

    const remediationSummary =
      doc.splitTextToSize(
        remediation.summary,
        contentWidth,
      );

    ensureSpace(
      remediationSummary.length * 4.5 + 5,
    );

    doc.text(
      remediationSummary,
      margin,
      y,
    );

    y +=
      remediationSummary.length * 4.5 + 6;

    doc.setFont("helvetica", "bold");
    doc.setFontSize(8);
    doc.setTextColor(45, 85, 65);

    doc.text(
      "Recommended Actions",
      margin,
      y,
    );

    y += 5;

    for (
      const action of remediation.actions
    ) {
      const actionLines =
        doc.splitTextToSize(
          `• ${action}`,
          contentWidth - 4,
        );

      const actionHeight =
        actionLines.length * 4.2 + 2;

      ensureSpace(actionHeight);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(8);
      doc.setTextColor(45, 70, 60);

      doc.text(
        actionLines,
        margin + 2,
        y,
      );

      y += actionHeight;
    }

    y += 8;
  }

  /* =======================================================
     COVER / EXECUTIVE SUMMARY
     ======================================================= */

  addHeader();

  doc.setTextColor(20, 55, 90);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(20);

  doc.text(
    "CalixAI Security Testing Report",
    margin,
    y,
  );

  y += 9;

  doc.setTextColor(90, 115, 140);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);

  doc.text(
    "API / DAST Security Assessment",
    margin,
    y,
  );

  y += 14;

  doc.setDrawColor(215, 225, 235);
  doc.line(
    margin,
    y,
    pageWidth - margin,
    y,
  );

  y += 10;

  addLabelValue(
    "Assessment",
    scanLabel,
  );

  addLabelValue(
    "Scan ID",
    String(scanId),
  );

  addLabelValue(
    "Target",
    target,
  );

  addLabelValue(
    "Generated",
    new Date().toLocaleString(),
  );

  addLabelValue(
    "Findings",
    String(findings.length),
  );

  /* =======================================================
     SEVERITY SUMMARY
     ======================================================= */

  addSectionTitle(
    "Executive Findings Summary",
  );

  const severitySummary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const finding of findings) {
    const severity =
      String(finding.severity || "INFO")
        .toLowerCase();

    if (severity === "critical") {
      severitySummary.critical += 1;
    } else if (severity === "high") {
      severitySummary.high += 1;
    } else if (severity === "medium") {
      severitySummary.medium += 1;
    } else if (severity === "low") {
      severitySummary.low += 1;
    } else {
      severitySummary.info += 1;
    }
  }

  const summaryItems = [
    ["Critical", severitySummary.critical],
    ["High", severitySummary.high],
    ["Medium", severitySummary.medium],
    ["Low", severitySummary.low],
    ["Informational", severitySummary.info],
  ];

  for (const [label, count] of summaryItems) {
    ensureSpace(9);

    doc.setFont("helvetica", "bold");
    doc.setFontSize(9);
    doc.setTextColor(55, 80, 105);

    doc.text(
      String(label),
      margin,
      y,
    );

    doc.setFont("helvetica", "bold");
    doc.setTextColor(20, 60, 100);

    doc.text(
      String(count),
      pageWidth - margin,
      y,
      {
        align: "right",
      },
    );

    y += 7;
  }

  y += 5;

  addSectionTitle(
    "Assessment Scope",
  );

  addWrappedText(
    "This report summarizes the security findings identified by the CalixAI API / DAST assessment engine for the selected target. Findings include validation status, confidence, affected URL and parameter information, technical details, and payload or evidence where available.",
    8.5,
  );

  /* =======================================================
     FINDINGS
     ======================================================= */

  if (findings.length === 0) {
    addSectionTitle(
      "Security Findings",
    );

    addWrappedText(
      "No findings were returned for this assessment.",
    );
  } else {
    addSectionTitle(
      `Security Findings (${findings.length})`,
    );

    findings.forEach(
      (finding, index) => {
        addFinding(
          finding,
          index,
        );
      },
    );
  }

  /* =======================================================
     FINAL FOOTERS
     ======================================================= */

  addFooter();

  const safeScanLabel =
    scanLabel
      .replace(/[^a-zA-Z0-9-_]/g, "-")
      .replace(/-+/g, "-");

  const filename =
    `CalixAI-Security-Testing-Report-${safeScanLabel || scanId}.pdf`;

  doc.save(filename);
}

export default function ScanDetails({
  scanId,
  scanLabel,
  target,
  onClose,
}: ScanDetailsProps) {
  const [findings, setFindings] =
    useState<ScanFinding[]>([]);

  const [selectedFinding, setSelectedFinding] =
    useState<ScanFinding | null>(null);

  const [loading, setLoading] =
    useState(false);

  const [error, setError] =
    useState("");

  /*
   * Keep a narrowed scan ID for all API/report actions.
   * This avoids TypeScript null errors.
   */
  useEffect(() => {
    if (scanId === null) {
      return;
    }

    const id: number = scanId;

    let cancelled = false;

    async function loadFindings() {
      try {
        setLoading(true);
        setError("");

        const response =
          await getScanFindings(
            id,
            1,
            100,
          );

        if (!cancelled) {
          setFindings(
            response.findings,
          );

          if (
            response.findings.length > 0
          ) {
            setSelectedFinding(
              response.findings[0],
            );
          } else {
            setSelectedFinding(null);
          }
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error
              ? err.message
              : "Unable to load findings.",
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadFindings();

    return () => {
      cancelled = true;
    };
  }, [scanId]);

  if (scanId === null) {
    return null;
  }

  const currentScanId: number = scanId;

  function downloadReport(
    format:
      | "json"
      | "html"
      | "csv",
  ) {
    window.open(
      getReportUrl(
        currentScanId,
        format,
      ),
      "_blank",
      "noopener,noreferrer",
    );
  }

  function downloadZip() {
    window.open(
      getReportZipUrl(
        currentScanId,
      ),
      "_blank",
      "noopener,noreferrer",
    );
  }

  function downloadPdf() {
    generateCalixAIPdf(
      currentScanId,
      scanLabel,
      target,
      findings,
    );
  }

  return (
    <div className="scan-details-overlay">
      <section className="scan-details-modal">
        <header className="scan-details-header">
          <div>
            <div className="scan-details-eyebrow">
              SECURITY ASSESSMENT
            </div>

            <h2>
              {scanLabel}
            </h2>

            <p>
              {target}
            </p>
          </div>

          <button
            className="scan-details-close"
            onClick={onClose}
            aria-label="Close"
          >
            <X size={22} />
          </button>
        </header>

        <div className="scan-details-toolbar">
          <div className="scan-report-label">
            <FileText size={19} />
            Download Report
          </div>

          <div className="scan-report-buttons">
            <button
              onClick={downloadPdf}
            >
              <Download size={17} />
              PDF
            </button>

            <button
              onClick={() =>
                downloadReport("html")
              }
            >
              <Download size={17} />
              HTML
            </button>

            <button
              onClick={() =>
                downloadReport("json")
              }
            >
              <Download size={17} />
              JSON
            </button>

            <button
              onClick={downloadZip}
            >
              <Download size={17} />
              ZIP
            </button>
          </div>
        </div>

        <div className="scan-details-content">
          <div className="scan-findings-panel">
            <div className="scan-findings-heading">
              <div>
                <h3>
                  Security Findings
                </h3>

                <p>
                  {findings.length} findings
                  identified by the
                  assessment.
                </p>
              </div>
            </div>

            {loading && (
              <div className="scan-details-state">
                Loading findings...
              </div>
            )}

            {!loading && error && (
              <div className="scan-details-state scan-details-error">
                <AlertTriangle size={20} />
                {error}
              </div>
            )}

            {!loading &&
              !error &&
              findings.length === 0 && (
                <div className="scan-details-state">
                  <CheckCircle2 size={22} />
                  No findings were returned
                  for this assessment.
                </div>
              )}

            {!loading &&
              !error &&
              findings.map(
                (finding, index) => (
                  <button
                    key={
                      finding.finding_id ??
                      index
                    }
                    className={`scan-finding-row ${
                      selectedFinding?.finding_id ===
                      finding.finding_id
                        ? "selected"
                        : ""
                    }`}
                    onClick={() =>
                      setSelectedFinding(
                        finding,
                      )
                    }
                  >
                    <span className="scan-finding-number">
                      #{index + 1}
                    </span>

                    <span className="scan-finding-type">
                      {finding.type}
                    </span>

                    <span
                      className={`scan-finding-severity ${severityClass(
                        finding.severity,
                      )}`}
                    >
                      {finding.severity}
                    </span>

                    <span className="scan-finding-status">
                      {finding.validated
                        ? "Validated"
                        : "Not Validated"}
                    </span>
                  </button>
                ),
              )}
          </div>

          <aside className="scan-finding-detail-panel">
            {selectedFinding ? (
              <div>
                <div className="scan-finding-detail-title">
                  <div>
                    <span className="scan-detail-eyebrow">
                      FINDING
                    </span>

                    <h3>
                      {selectedFinding.type}
                    </h3>
                  </div>

                  <span
                    className={`scan-finding-severity ${severityClass(
                      selectedFinding.severity,
                    )}`}
                  >
                    {selectedFinding.severity}
                  </span>
                </div>

                <div className="scan-detail-grid">
                  <div className="scan-detail-card">
                    <span>
                      Finding ID
                    </span>

                    <strong>
                      #
                      {
                        selectedFinding.finding_id
                      }
                    </strong>
                  </div>

                  <div className="scan-detail-card">
                    <span>
                      URL
                    </span>

                    <strong>
                      {selectedFinding.url ||
                        "N/A"}
                    </strong>
                  </div>

                  <div className="scan-detail-card">
                    <span>
                      Parameter
                    </span>

                    <strong>
                      {selectedFinding.parameter ||
                        "N/A"}
                    </strong>
                  </div>

                  <div className="scan-detail-card">
                    <span>
                      Validation
                    </span>

                    <strong>
                      {selectedFinding.validated
                        ? "Confirmed"
                        : "Not Confirmed"}
                    </strong>
                  </div>

                  <div className="scan-detail-card">
                    <span>
                      Status
                    </span>

                    <strong>
                      {selectedFinding.status ||
                        "N/A"}
                    </strong>
                  </div>

                  <div className="scan-detail-card">
                    <span>
                      Confidence
                    </span>

                    <strong>
                      {formatConfidence(
                        selectedFinding.confidence,
                      )}
                    </strong>
                  </div>
                </div>

                <div className="scan-detail-block">
                  <span>
                    Details
                  </span>

                  <pre>
                    {safeText(
                      selectedFinding.details,
                    ) ||
                      "No additional details available."}
                  </pre>
                </div>

                <div className="scan-detail-block">
                  <span>
                    Payload / Evidence
                  </span>

                  <pre>
                    {safeText(
                      selectedFinding.payload,
                    ) ||
                      "No payload or evidence recorded."}
                  </pre>
                </div>

                <div className="calixai-remediation">
                  <div className="calixai-remediation-header">
                    <div>
                      <span>
                        REMEDIATION
                      </span>

                      <h4>
                        Recommended Fix
                      </h4>
                    </div>
                  </div>

                  <p className="calixai-remediation-summary">
                    {
                      getCalixAIRemediation(
                        selectedFinding,
                      ).summary
                    }
                  </p>

                  <div className="calixai-remediation-actions">
                    <strong>
                      Recommended Actions
                    </strong>

                    <ul>
                      {
                        getCalixAIRemediation(
                          selectedFinding,
                        ).actions.map(
                          (action, index) => (
                            <li key={index}>
                              <CheckCircle2
                                size={17}
                              />
                              <span>
                                {action}
                              </span>
                            </li>
                          ),
                        )
                      }
                    </ul>
                  </div>
                </div>
              </div>
            ) : (
              <div className="scan-details-state">
                Select a finding to view
                its details.
              </div>
            )}
          </aside>
        </div>
      </section>
    </div>
  );
}
