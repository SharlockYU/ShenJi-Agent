"""
神机 (ShenJi) - 智能渗透测试 Agent 系统

基于 LangGraph + LangChain 的智能渗透测试辅助工具
持续推理循环 | 状态累积 | 智能选择 | 自动停止
"""

__version__ = "2.0.0"
__codename__ = "ShenJi"
__author__ = "ShenJi Team"

from agent.pentest_agent import PentestAgent
from agent.smart_agent import ShenJiAgent
from agent.core.models import RiskLevel, StepStatus

__all__ = [
    "PentestAgent",
    "ShenJiAgent",
    "RiskLevel",
    "StepStatus",
]
