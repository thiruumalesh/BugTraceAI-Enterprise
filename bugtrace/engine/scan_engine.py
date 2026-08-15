from typing import Dict, List, Optional
from bugtrace.core.scan_context import ScanContext
from bugtrace.core.event_bus import EventBus
from bugtrace.core.worker_pool import WorkerPool
from bugtrace.core.orchestrator import AgentOrchestrator


class ScanEngine:
    def __init__(self, scan_context: ScanContext, event_bus: EventBus, worker_pool: WorkerPool):
        self.scan_context = scan_context
        self.event_bus = event_bus
        self.worker_pool = worker_pool
        self.agent_orchestrator = AgentOrchestrator(
            scan_context=scan_context,
            event_bus=event_bus,
            worker_pool=worker_pool
        )

    async def run(self, scan_context: ScanContext):
        # Discovery phase - return discovered targets
        discovered_targets = self._discover_targets()

        # If no URLs were discovered, use the original target URL
        if not discovered_targets:
            discovered_targets = [scan_context.target_url]

        # Store targets in ScanContext
        scan_context.discovered_targets = discovered_targets

        # Technology detection
        detected_technologies = self._detect_technologies()
        scan_context.technologies = detected_technologies

        # Execute AgentOrchestrator to get the execution plan
        execution_plan = self.agent_orchestrator.execute()

        # Store execution plan in ScanContext
        scan_context.execution_plan = execution_plan

        # Update progress with the discovered targets, technologies, and execution plan
        self.event_bus.publish("scan_progress_update", {
            "phase": "discovery_and_technology_detection",
            "status": "completed",
            "details": {
                "discovered_targets": discovered_targets,
                "detected_technologies": detected_technologies,
                "execution_plan": execution_plan
            }
        })

        # Return the scan context with the execution plan
        return scan_context
