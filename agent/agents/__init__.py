"""
多Agent系统 - 支持总指挥+工作Agent模式
"""

from agent.agents.base import BaseAgent, AgentRole, AgentMessage, AgentTask
from agent.agents.master import MasterAgent
from agent.agents.worker import WorkerAgent
from agent.agents.recon_agent import ReconAgent
from agent.agents.scan_agent import ScanAgent
from agent.agents.enum_agent import EnumAgent
from agent.agents.vuln_agent import VulnAgent
from agent.agents.coordinator import AgentCoordinator

__all__ = [
    "BaseAgent",
    "AgentRole",
    "AgentMessage",
    "AgentTask",
    "MasterAgent",
    "WorkerAgent",
    "ReconAgent",
    "ScanAgent",
    "EnumAgent",
    "VulnAgent",
    "AgentCoordinator",
]
