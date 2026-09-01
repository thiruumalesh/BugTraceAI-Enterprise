export type ScanStatus =
  | "PENDING"
  | "INITIALIZING"
  | "RUNNING"
  | "PAUSED"
  | "COMPLETED"
  | "STOPPED"
  | "FAILED"
  | "CANCELLED";

export interface CreateScanRequest {
  target_url: string;
  scan_type?: string;
  scan_depth?: string;
  safe_mode?: boolean | null;
  max_depth?: number;
  max_urls?: number;
  resume?: boolean;
  use_vertical?: boolean;
  focused_agents?: string[];
  param?: string | null;
  auth_token?: string | null;
  auth?: Record<string, unknown> | null;
  url_list?: string[] | null;
}

export interface ScanStatusResponse {
  scan_id: number;
  target: string;
  status: ScanStatus;
  progress: number;
  uptime_seconds?: number | null;
  findings_count: number;
  active_agent?: string | null;
  phase?: string | null;
  origin?: string;
  enrichment_status?: string | null;
  scan_type?: string | null;
  max_depth?: number | null;
  max_urls?: number | null;
  provider?: string | null;
}

export interface ScanSummary {
  scan_id: number;
  target: string;
  status: ScanStatus;
  progress: number;
  timestamp: string;
  origin?: string;
  enrichment_status?: string | null;
  has_report?: boolean;
  recovery_available?: boolean;
  scan_type?: string | null;
  max_depth?: number | null;
  max_urls?: number | null;
  provider?: string | null;
  findings_count?: number;
}

export interface ScanListResponse {
  scans: ScanSummary[];
  total: number;
  page: number;
  per_page: number;
}

/* =========================================================
   FINDINGS
   ========================================================= */

export type FindingSeverity =
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "LOW"
  | "INFO"
  | string;

export interface ScanFinding {
  finding_id: number;
  type: string;
  severity: FindingSeverity;
  details: string;
  payload: string;
  url: string;
  parameter: string;
  validated: boolean;
  status: string;
  confidence: number;
}

export interface ScanFindingsResponse {
  findings: ScanFinding[];
  total: number;
  page: number;
  per_page: number;
  scan_id: number;
}

export interface FindingSeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

const API_BASE = "/bugtrace-api";

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });

  const responseText = await response.text();

  let data: unknown = null;

  if (responseText) {
    try {
      data = JSON.parse(responseText);
    } catch {
      data = responseText;
    }
  }

  if (!response.ok) {
    let message = `CalixAI API error (${response.status})`;

    if (
      data &&
      typeof data === "object" &&
      "detail" in data
    ) {
      message = String(
        (data as { detail?: unknown }).detail ?? message,
      );
    }

    throw new Error(message);
  }

  return data as T;
}

export async function createScan(
  requestBody: CreateScanRequest,
): Promise<ScanStatusResponse> {
  return request<ScanStatusResponse>("/api/scans", {
    method: "POST",
    body: JSON.stringify(requestBody),
  });
}

export async function listScans(): Promise<ScanListResponse> {
  return request<ScanListResponse>("/api/scans");
}

export async function getScanStatus(
  scanId: number,
): Promise<ScanStatusResponse> {
  return request<ScanStatusResponse>(
    `/api/scans/${scanId}/status`,
  );
}

export async function getScanFindings(
  scanId: number,
  page = 1,
  perPage = 50,
): Promise<ScanFindingsResponse> {
  return request<ScanFindingsResponse>(
    `/api/scans/${scanId}/findings?page=${page}&per_page=${perPage}`,
  );
}

export function summarizeFindings(
  findings: ScanFinding[],
): FindingSeveritySummary {
  const summary: FindingSeveritySummary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: findings.length,
  };

  for (const finding of findings) {
    switch (finding.severity.toUpperCase()) {
      case "CRITICAL":
        summary.critical += 1;
        break;

      case "HIGH":
        summary.high += 1;
        break;

      case "MEDIUM":
        summary.medium += 1;
        break;

      case "LOW":
        summary.low += 1;
        break;

      case "INFO":
      case "INFORMATIONAL":
        summary.info += 1;
        break;

      default:
        break;
    }
  }

  return summary;
}

export async function stopScan(
  scanId: number,
): Promise<{
  scan_id: number;
  status: string;
  message: string;
}> {
  return request(`/api/scans/${scanId}/stop`, {
    method: "POST",
  });
}

/* =========================================================
   SCHEDULER
   ========================================================= */

export type ScheduledScanType =
  | "DAST"
  | "MAST"
  | "NETWORK";

export type ScheduleFrequency =
  | "once"
  | "hourly"
  | "daily"
  | "weekly"
  | "monthly"
  | "cron";

export type ScheduleStatus =
  | "enabled"
  | "disabled";

export type ExecutionStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export interface ScanSchedule {
  id: number;
  name: string;
  scan_type: ScheduledScanType;
  target: string;
  configuration: Record<string, unknown>;
  artifact_path?: string | null;
  frequency: ScheduleFrequency;
  cron_expression?: string | null;
  timezone: string;
  status: ScheduleStatus;
  next_run_at?: string | null;
  last_run_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ScheduleListResponse {
  schedules: ScanSchedule[];
}

export interface CreateScheduleRequest {
  name: string;
  scan_type: ScheduledScanType;
  target: string;
  configuration?: Record<string, unknown>;
  artifact_path?: string | null;
  frequency: ScheduleFrequency;
  cron_expression?: string | null;
  timezone?: string;
  run_at?: string | null;
}

export interface ScheduleExecution {
  id: number;
  schedule_id: number;
  scan_type: ScheduledScanType;
  status: ExecutionStatus;
  started_at?: string | null;
  completed_at?: string | null;
  duration_seconds?: number | null;
  scan_id?: string | number | null;
  scan_hash?: string | null;
  error?: string | null;
  results?: unknown;
  created_at: string;
}

export interface ScheduleExecutionsResponse {
  schedule_id: number;
  executions: ScheduleExecution[];
}

export interface ScheduleRunResponse {
  status: string;
  schedule_id: number;
  execution_id?: number;
  scan_id?: string | number | null;
  message?: string;
}

/**
 * List all scheduled scans.
 */
export async function listSchedules(): Promise<ScheduleListResponse> {
  return request<ScheduleListResponse>(
    "/api/schedules",
  );
}

/**
 * Get one scheduled scan.
 */
export async function getSchedule(
  scheduleId: number,
): Promise<ScanSchedule> {
  return request<ScanSchedule>(
    `/api/schedules/${scheduleId}`,
  );
}

/**
 * Create a scheduled scan.
 */
export async function createSchedule(
  requestBody: CreateScheduleRequest,
): Promise<ScanSchedule> {
  return request<ScanSchedule>(
    "/api/schedules",
    {
      method: "POST",
      body: JSON.stringify(requestBody),
    },
  );
}

/**
 * Delete a scheduled scan.
 */
export async function deleteSchedule(
  scheduleId: number,
): Promise<{
  status: string;
  schedule_id: number;
}> {
  return request(
    `/api/schedules/${scheduleId}`,
    {
      method: "DELETE",
    },
  );
}

/**
 * Enable a scheduled scan.
 */
export async function enableSchedule(
  scheduleId: number,
): Promise<ScanSchedule> {
  return request<ScanSchedule>(
    `/api/schedules/${scheduleId}/enable`,
    {
      method: "POST",
    },
  );
}

/**
 * Disable a scheduled scan.
 */
export async function disableSchedule(
  scheduleId: number,
): Promise<ScanSchedule> {
  return request<ScanSchedule>(
    `/api/schedules/${scheduleId}/disable`,
    {
      method: "POST",
    },
  );
}

/**
 * Run a scheduled scan immediately.
 */
export async function runScheduleNow(
  scheduleId: number,
): Promise<ScheduleRunResponse> {
  return request<ScheduleRunResponse>(
    `/api/schedules/${scheduleId}/run`,
    {
      method: "POST",
    },
  );
}

/**
 * Get execution history for a schedule.
 */
export async function getScheduleExecutions(
  scheduleId: number,
): Promise<ScheduleExecutionsResponse> {
  return request<ScheduleExecutionsResponse>(
    `/api/schedules/${scheduleId}/executions`,
  );
}


/* =========================================================
   REPORTS
   ========================================================= */

export function getReportUrl(
  scanId: number,
  format: "json" | "html" | "pdf" | "csv",
): string {
  return `${API_BASE}/api/scans/${scanId}/report/${format}`;
}

export function getReportZipUrl(scanId: number): string {
  return `${API_BASE}/api/scans/${scanId}/report-zip`;
}
