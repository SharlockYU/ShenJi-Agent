"""
工具模块 - 安全工具的封装和注册
"""

from agent.tools.base import BaseTool, ToolRegistry
from agent.tools.nmap import NmapTool
from agent.tools.nikto import NiktoTool
from agent.tools.gobuster import GobusterTool
from agent.tools.nuclei import NucleiTool
from agent.tools.http import HTTPTool

# 初始化工具注册表
registry = ToolRegistry()

# 注册默认工具
registry.register(NmapTool)
registry.register(NiktoTool)
registry.register(GobusterTool)
registry.register(NucleiTool)
registry.register(HTTPTool)

__all__ = [
    "BaseTool",
    "ToolRegistry",
    "registry",
    "NmapTool",
    "NiktoTool", 
    "GobusterTool",
    "NucleiTool",
    "HTTPTool",
]
