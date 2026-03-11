"""
Agent基础类和数据模型
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional, List, Dict, Any, Callable
from datetime import datetime
from pydantic import BaseModel, Field
from rich.console import Console

from agent.core.models import TargetInfo, ToolResult, Step, RiskLevel


class AgentRole(str, Enum):
    """Agent角色枚举"""
    MASTER = "master"           # 总指挥 - 负责决策
    RECON = "recon"             # 侦察Agent - 负责信息收集
    SCAN = "scan"               # 扫描Agent - 负责端口扫描
    ENUM = "enum"               # 枚举Agent - 负责目录枚举
    VULN = "vuln"               # 漏洞Agent - 负责漏洞检测


class AgentStatus(str, Enum):
    """Agent状态枚举"""
    IDLE = "idle"               # 空闲
    WORKING = "working"         # 工作中
    WAITING = "waiting"         # 等待中
    COMPLETED = "completed"     # 已完成
    ERROR = "error"             # 错误


class TaskPriority(int, Enum):
    """任务优先级"""
    CRITICAL = 1    # 最高优先级
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    BACKGROUND = 5  # 后台任务


class AgentTask(BaseModel):
    """Agent任务"""
    id: str = Field(default_factory=lambda: f"task_{datetime.now().strftime('%Y%m%d%H%M%S%f')}")
    name: str = Field(..., description="任务名称")
    description: str = Field(default="", description="任务描述")
    target: TargetInfo = Field(..., description="目标信息")
    tool: str = Field(..., description="使用的工具")
    command: str = Field(..., description="执行命令")
    priority: TaskPriority = Field(default=TaskPriority.MEDIUM, description="优先级")
    assigned_to: Optional[str] = Field(None, description="分配给的Agent")
    status: str = Field(default="pending", description="任务状态")
    result: Optional[ToolResult] = Field(None, description="执行结果")
    context: Dict[str, Any] = Field(default_factory=dict, description="任务上下文")
    created_at: datetime = Field(default_factory=datetime.now)
    started_at: Optional[datetime] = Field(None)
    completed_at: Optional[datetime] = Field(None)
    
    def to_step(self) -> Step:
        """转换为Step对象"""
        return Step(
            id=self.id,
            name=self.name,
            tool=self.tool,
            command=self.command,
            description=self.description,
            risk_level=RiskLevel.LOW,
            status=self.status,
            result=self.result,
            metadata=self.context
        )


class AgentMessage(BaseModel):
    """Agent消息"""
    id: str = Field(default_factory=lambda: f"msg_{datetime.now().strftime('%Y%m%d%H%M%S%f')}")
    from_agent: str = Field(..., description="发送者")
    to_agent: str = Field(..., description="接收者")
    message_type: str = Field(..., description="消息类型")
    content: Dict[str, Any] = Field(default_factory=dict, description="消息内容")
    timestamp: datetime = Field(default_factory=datetime.now)
    requires_response: bool = Field(default=False, description="是否需要响应")


class Decision(BaseModel):
    """总指挥决策"""
    id: str = Field(default_factory=lambda: f"dec_{datetime.now().strftime('%Y%m%d%H%M%S%f')}")
    reasoning: str = Field(..., description="决策推理过程")
    action: str = Field(..., description="决策动作")
    tasks: List[AgentTask] = Field(default_factory=list, description="生成的任务")
    is_complete: bool = Field(default=False, description="是否完成任务")
    complete_reason: str = Field(default="", description="完成原因")
    flag_found: bool = Field(default=False, description="是否找到flag")
    flag_value: str = Field(default="", description="flag值")
    confidence: float = Field(default=0.8, description="置信度")


class BaseAgent(ABC):
    """
    Agent基类
    定义所有Agent的基本接口和行为
    """
    
    def __init__(
        self,
        agent_id: str,
        role: AgentRole,
        config: Optional[Dict[str, Any]] = None
    ):
        self.agent_id = agent_id
        self.role = role
        self.config = config or {}
        self.console = Console()
        self.status = AgentStatus.IDLE
        self.message_handler: Optional[Callable[[AgentMessage], None]] = None
        self._task_queue: List[AgentTask] = []
        self._completed_tasks: List[AgentTask] = []
        
    @property
    def name(self) -> str:
        """获取Agent名称"""
        return f"{self.role.value}_{self.agent_id}"
    
    def set_message_handler(self, handler: Callable[[AgentMessage], None]) -> None:
        """设置消息处理器"""
        self.message_handler = handler
    
    def send_message(
        self,
        to_agent: str,
        message_type: str,
        content: Dict[str, Any],
        requires_response: bool = False
    ) -> AgentMessage:
        """发送消息给其他Agent"""
        message = AgentMessage(
            from_agent=self.name,
            to_agent=to_agent,
            message_type=message_type,
            content=content,
            requires_response=requires_response
        )
        
        if self.message_handler:
            self.message_handler(message)
        
        return message
    
    def receive_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """接收消息"""
        self._log(f"收到消息 [{message.message_type}] 来自 {message.from_agent}")
        return self.handle_message(message)
    
    @abstractmethod
    def handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理收到的消息"""
        pass
    
    @abstractmethod
    def execute_task(self, task: AgentTask) -> ToolResult:
        """执行任务"""
        pass
    
    def add_task(self, task: AgentTask) -> None:
        """添加任务到队列"""
        task.assigned_to = self.name
        self._task_queue.append(task)
        self._task_queue.sort(key=lambda t: t.priority.value)
        self._log(f"添加任务: {task.name}")
    
    def get_next_task(self) -> Optional[AgentTask]:
        """获取下一个待执行任务"""
        for task in self._task_queue:
            if task.status == "pending":
                return task
        return None
    
    def complete_task(self, task: AgentTask, result: ToolResult) -> None:
        """完成任务"""
        task.status = "completed"
        task.result = result
        task.completed_at = datetime.now()
        self._completed_tasks.append(task)
        if task in self._task_queue:
            self._task_queue.remove(task)
        self._log(f"完成任务: {task.name}")
    
    def get_capabilities(self) -> Dict[str, Any]:
        """获取Agent能力描述"""
        return {
            "agent_id": self.agent_id,
            "role": self.role.value,
            "status": self.status.value,
            "tools": [],
            "description": "Base Agent"
        }
    
    def _log(self, message: str, level: str = "info") -> None:
        """日志输出"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        color_map = {
            "info": "cyan",
            "success": "green",
            "warning": "yellow",
            "error": "red"
        }
        color = color_map.get(level, "white")
        self.console.print(f"[{color}][{timestamp}][/{color}] [{self.name}] {message}")
