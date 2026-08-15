from typing import Dict, List
from bugtrace.core.scan_context import ScanContext
from bugtrace.core.event_bus import EventBus
from bugtrace.core.worker_pool import WorkerPool


class AgentOrchestrator:
    def __init__(self, scan_context: ScanContext, event_bus: EventBus, worker_pool: WorkerPool):
        self.scan_context = scan_context
        self.event_bus = event_bus
        self.worker_pool = worker_pool
        self.agents = []

    def execute(self) -> Dict[str, any]:
        # Discover and register available agents
        self.agents = self._discover_agents()
        
        # Initialize shared findings list
        shared_findings = []
        failed_agents = []
        
        # Execute each agent
        for agent in self.agents:
            # Skip disabled agents
            if not agent.get("enabled", True):
                continue

            # Execute the agent
            try:
                # Get findings from agent
                agent_findings = agent["scan"](self.scan_context)
                
                # Append findings to shared list
                shared_findings.extend(agent_findings)
            except Exception as e:
                # Continue executing remaining agents even if one fails
                self.event_bus.publish("agent_execution_error", {
                    "agent_name": agent["name"],
                    "error": str(e)
                })
                failed_agents.append(agent["name"])
                continue

        # Store findings in ScanContext
        self.scan_context.findings = shared_findings
        
        # Return execution summary with findings
        return {
            "status": "completed",
            "findings": shared_findings,
            "agents_executed": len(self.agents),
            "agents_failed": len(failed_agents),
            "failed_agents": failed_agents,
            "execution_time": "N/A"
        }

    def _discover_agents(self) -> List[Dict[str, any]]:
        # This method should discover and return a list of available agent configurations
        # For the purpose of this task, we'll return a placeholder list
        return [
            {
                "name": "DASTySASTAgent",
                "enabled": True,
                "scan": lambda scan_context: ["Finding 1", "Finding 2"]
            },
            {
                "name": "NucleiAgent",
                "enabled": True,
                "scan": lambda scan_context: ["Finding 3", "Finding 4"]
            },
            {
                "name": "SQLMapAgent",
                "enabled": True,
                "scan": lambda scan_context: ["Finding 5", "Finding 6"]
            }
        ]
