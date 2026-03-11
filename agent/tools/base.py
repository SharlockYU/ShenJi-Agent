"""
工具基类和注册表
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Type
from dataclasses import dataclass, field

from agent.core.models import RiskLevel, Finding


@dataclass
class ToolInfo:
    """工具信息"""
    name: str
    description: str
    risk_level: RiskLevel
    category: str
    examples: List[str] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=dict)


class BaseTool(ABC):
    """
    工具基类
    所有安全工具都需要继承此类
    """
    
    # 工具信息（子类必须覆盖）
    info: ToolInfo = None
    
    @classmethod
    @abstractmethod
    def get_info(cls) -> ToolInfo:
        """获取工具信息"""
        pass
    
    @classmethod
    @abstractmethod
    def build_command(cls, target: str, options: Optional[Dict[str, Any]] = None) -> str:
        """
        构建执行命令
        
        Args:
            target: 目标地址
            options: 可选参数
            
        Returns:
            完整的命令字符串
        """
        pass
    
    @classmethod
    @abstractmethod
    def parse_output(cls, output: str) -> List[Finding]:
        """
        解析工具输出
        
        Args:
            output: 工具的原始输出
            
        Returns:
            发现的问题列表
        """
        pass
    
    @classmethod
    def get_name(cls) -> str:
        """获取工具名称"""
        return cls.get_info().name


class ToolRegistry:
    """
    工具注册表
    管理所有可用的安全工具
    """
    
    def __init__(self):
        self._tools: Dict[str, Type[BaseTool]] = {}
    
    def register(self, tool_class: Type[BaseTool]) -> None:
        """注册工具"""
        info = tool_class.get_info()
        self._tools[info.name.lower()] = tool_class
    
    def get(self, name: str) -> Optional[Type[BaseTool]]:
        """获取工具类"""
        return self._tools.get(name.lower())
    
    def list_tools(self) -> List[str]:
        """列出所有注册的工具"""
        return list(self._tools.keys())
    
    def get_all_info(self) -> Dict[str, ToolInfo]:
        """获取所有工具信息"""
        return {name: cls.get_info() for name, cls in self._tools.items()}
    
    def __contains__(self, name: str) -> bool:
        return name.lower() in self._tools
