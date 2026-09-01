import { useEffect, useState } from "react";
import {
  CalendarClock,
  CheckCircle2,
  Clock3,
  Play,
  Plus,
  RefreshCw,
  Trash2,
  XCircle,
} from "lucide-react";

import {
  createSchedule,
  deleteSchedule,
  disableSchedule,
  enableSchedule,
  getScheduleExecutions,
  listSchedules,
  runScheduleNow,
  type ScanSchedule,
  type ScheduleExecution,
} from "../services/bugtraceApi";

import "./ScheduledScans.css";

export default function ScheduledScans() {
  const [schedules, setSchedules] = useState<ScanSchedule[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [executions, setExecutions] = useState<
    Record<number, ScheduleExecution[]>
  >({});
  const [runningId, setRunningId] = useState<number | null>(null);

  const loadSchedules = async () => {
    try {
      setLoading(true);
      const response = await listSchedules();
      setSchedules(response.schedules);
    } catch (error) {
      console.error("Failed to load schedules:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadSchedules();
  }, []);

  const handleRunNow = async (id: number) => {
    try {
      setRunningId(id);
      await runScheduleNow(id);
      await loadSchedules();
    } catch (error) {
      console.error("Failed to run schedule:", error);
      alert(
        error instanceof Error
          ? error.message
          : "Failed to start scheduled scan.",
      );
    } finally {
      setRunningId(null);
    }
  };

  const handleToggle = async (schedule: ScanSchedule) => {
    try {
      if (schedule.status === "enabled") {
        await disableSchedule(schedule.id);
      } else {
        await enableSchedule(schedule.id);
      }

      await loadSchedules();
    } catch (error) {
      console.error("Failed to update schedule:", error);
    }
  };

  const handleDelete = async (id: number) => {
    if (!window.confirm("Delete this scheduled scan?")) {
      return;
    }

    try {
      await deleteSchedule(id);
      await loadSchedules();
    } catch (error) {
      console.error("Failed to delete schedule:", error);
    }
  };

  const handleExecutions = async (id: number) => {
    try {
      const response = await getScheduleExecutions(id);

      setExecutions((current) => ({
        ...current,
        [id]: response.executions,
      }));
    } catch (error) {
      console.error("Failed to load executions:", error);
    }
  };

  return (
    <div className="scheduled-scans-page">
      <section className="scheduled-header">
        <div>
          <div className="scheduled-eyebrow">
            AUTOMATION & CONTINUOUS SECURITY
          </div>

          <h2>Scheduled Scans</h2>

          <p>
            Automate recurring API / DAST, MAST and Network Pentest
            assessments from one security operations view.
          </p>
        </div>

        <button
          className="schedule-primary-button"
          onClick={() => setShowCreate(true)}
        >
          <Plus size={18} />
          Schedule Scan
        </button>
      </section>

      <section className="schedule-summary">
        <div className="schedule-summary-card">
          <CalendarClock size={22} />
          <div>
            <span>Scheduled</span>
            <strong>{schedules.length}</strong>
          </div>
        </div>

        <div className="schedule-summary-card">
          <CheckCircle2 size={22} />
          <div>
            <span>Enabled</span>
            <strong>
              {schedules.filter((item) => item.status === "enabled").length}
            </strong>
          </div>
        </div>

        <div className="schedule-summary-card">
          <Clock3 size={22} />
          <div>
            <span>Recurring</span>
            <strong>
              {
                schedules.filter(
                  (item) => item.frequency !== "once",
                ).length
              }
            </strong>
          </div>
        </div>
      </section>

      <section className="scheduled-list-card">
        <div className="scheduled-list-header">
          <div>
            <h3>Security Scan Schedules</h3>
            <p>Manage automated assessments across all testing domains.</p>
          </div>

          <button
            className="schedule-refresh-button"
            onClick={() => void loadSchedules()}
            title="Refresh schedules"
          >
            <RefreshCw size={17} />
          </button>
        </div>

        {loading ? (
          <div className="schedule-empty">
            Loading scheduled scans...
          </div>
        ) : schedules.length === 0 ? (
          <div className="schedule-empty">
            <CalendarClock size={42} />
            <strong>No scheduled scans</strong>
            <span>
              Create your first recurring security assessment.
            </span>
          </div>
        ) : (
          <div className="schedule-table-wrapper">
            <table className="schedule-table">
              <thead>
                <tr>
                  <th>NAME</th>
                  <th>TYPE</th>
                  <th>TARGET</th>
                  <th>FREQUENCY</th>
                  <th>NEXT RUN</th>
                  <th>STATUS</th>
                  <th>ACTIONS</th>
                </tr>
              </thead>

              <tbody>
                {schedules.map((schedule) => (
                  <tr key={schedule.id}>
                    <td>
                      <strong>{schedule.name}</strong>
                    </td>

                    <td>
                      <span
                        className={`schedule-type schedule-type-${schedule.scan_type.toLowerCase()}`}
                      >
                        {schedule.scan_type}
                      </span>
                    </td>

                    <td className="schedule-target">
                      {schedule.target}
                    </td>

                    <td>
                      <span className="schedule-frequency">
                        {schedule.frequency}
                      </span>
                    </td>

                    <td>
                      {schedule.next_run_at
                        ? new Date(
                            schedule.next_run_at,
                          ).toLocaleString()
                        : "Pending"}
                    </td>

                    <td>
                      <span
                        className={`schedule-status ${
                          schedule.status === "enabled"
                            ? "schedule-enabled"
                            : "schedule-disabled"
                        }`}
                      >
                        {schedule.status === "enabled" ? (
                          <CheckCircle2 size={14} />
                        ) : (
                          <XCircle size={14} />
                        )}

                        {schedule.status}
                      </span>
                    </td>

                    <td>
                      <div className="schedule-actions">
                        <button
                          onClick={() =>
                            void handleRunNow(schedule.id)
                          }
                          disabled={runningId === schedule.id}
                          title="Run Now"
                        >
                          <Play size={15} />
                        </button>

                        <button
                          onClick={() =>
                            void handleToggle(schedule)
                          }
                          title={
                            schedule.status === "enabled"
                              ? "Disable"
                              : "Enable"
                          }
                        >
                          {schedule.status === "enabled" ? (
                            <XCircle size={15} />
                          ) : (
                            <CheckCircle2 size={15} />
                          )}
                        </button>

                        <button
                          onClick={() =>
                            void handleExecutions(schedule.id)
                          }
                          title="Execution History"
                        >
                          <Clock3 size={15} />
                        </button>

                        <button
                          className="schedule-delete"
                          onClick={() =>
                            void handleDelete(schedule.id)
                          }
                          title="Delete"
                        >
                          <Trash2 size={15} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {Object.entries(executions).map(
              ([scheduleId, items]) => (
                <div
                  className="execution-history"
                  key={scheduleId}
                >
                  <h4>
                    Execution History — Schedule #{scheduleId}
                  </h4>

                  {items.length === 0 ? (
                    <p>No executions yet.</p>
                  ) : (
                    items.map((execution) => (
                      <div
                        className="execution-row"
                        key={execution.id}
                      >
                        <span>{execution.status}</span>
                        <span>
                          {execution.started_at
                            ? new Date(
                                execution.started_at,
                              ).toLocaleString()
                            : "Queued"}
                        </span>
                        <span>
                          {execution.duration_seconds
                            ? `${execution.duration_seconds}s`
                            : "—"}
                        </span>
                      </div>
                    ))
                  )}
                </div>
              ),
            )}
          </div>
        )}
      </section>

      {showCreate && (
        <ScheduleCreateModal
          onClose={() => setShowCreate(false)}
          onCreated={async () => {
            setShowCreate(false);
            await loadSchedules();
          }}
        />
      )}
    </div>
  );
}

function ScheduleCreateModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: () => Promise<void>;
}) {
  const [name, setName] = useState("");
  const [scanType, setScanType] = useState<
    "DAST" | "MAST" | "NETWORK"
  >("DAST");
  const [target, setTarget] = useState("");
  const [frequency, setFrequency] = useState<
    "once" | "hourly" | "daily" | "weekly" | "monthly" | "cron"
  >("daily");
  const [runAt, setRunAt] = useState("");
  const [timezone, setTimezone] = useState("Asia/Kolkata");
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (
    event: React.FormEvent,
  ) => {
    event.preventDefault();

    if (!name.trim() || !target.trim()) {
      alert("Name and target are required.");
      return;
    }

    try {
      setSubmitting(true);

      await createSchedule({
        name: name.trim(),
        scan_type: scanType,
        target: target.trim(),
        configuration: {},
        frequency,
        timezone,
        run_at: runAt
          ? new Date(runAt).toISOString()
          : undefined,
      });

      await onCreated();
    } catch (error) {
      console.error("Failed to create schedule:", error);

      alert(
        error instanceof Error
          ? error.message
          : "Failed to create schedule.",
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="schedule-modal-overlay"
      onMouseDown={onClose}
    >
      <div
        className="schedule-modal"
        onMouseDown={(event) =>
          event.stopPropagation()
        }
      >
        <div className="schedule-modal-header">
          <div>
            <div className="scheduled-eyebrow">
              SECURITY AUTOMATION
            </div>
            <h3>Schedule Security Scan</h3>
          </div>

          <button
            className="schedule-modal-close"
            onClick={onClose}
          >
            <XCircle size={20} />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <label>
            Schedule Name
            <input
              value={name}
              onChange={(event) =>
                setName(event.target.value)
              }
              placeholder="Production API Weekly Scan"
            />
          </label>

          <label>
            Security Test
            <select
              value={scanType}
              onChange={(event) =>
                setScanType(
                  event.target.value as
                    | "DAST"
                    | "MAST"
                    | "NETWORK",
                )
              }
            >
              <option value="DAST">API / DAST</option>
              <option value="MAST">MAST</option>
              <option value="NETWORK">
                Network Pentest
              </option>
            </select>
          </label>

          <label>
            Target
            <input
              value={target}
              onChange={(event) =>
                setTarget(event.target.value)
              }
              placeholder={
                scanType === "MAST"
                  ? "APK / IPA path or asset"
                  : "https://example.com"
              }
            />
          </label>

          <div className="schedule-form-grid">
            <label>
              Frequency
              <select
                value={frequency}
                onChange={(event) =>
                  setFrequency(
                    event.target.value as typeof frequency,
                  )
                }
              >
                <option value="once">Once</option>
                <option value="hourly">Hourly</option>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
                <option value="cron">Cron</option>
              </select>
            </label>

            <label>
              Timezone
              <input
                value={timezone}
                onChange={(event) =>
                  setTimezone(event.target.value)
                }
              />
            </label>
          </div>

          <label>
            Run At
            <input
              type="datetime-local"
              value={runAt}
              onChange={(event) =>
                setRunAt(event.target.value)
              }
            />
          </label>

          <div className="schedule-modal-actions">
            <button
              type="button"
              className="schedule-cancel-button"
              onClick={onClose}
            >
              Cancel
            </button>

            <button
              type="submit"
              className="schedule-primary-button"
              disabled={submitting}
            >
              <CalendarClock size={17} />
              {submitting
                ? "Creating..."
                : "Create Schedule"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
