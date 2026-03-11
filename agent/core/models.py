"""
数据模型定义 - 定义系统中使用的所有数据结构
"""

from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """风险等级枚举"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    def get_display(self) -> str:
        """获取显示文本"""
        displays = {
            RiskLevel.LOW: "🟢 低",
            RiskLevel.MEDIUM: "🟡 中",
            RiskLevel.HIGH: "🟠 高",
            RiskLevel.CRITICAL: "🔴 极高"
        }
        return displays[self]


class StepStatus(str, Enum):
    """步骤状态枚举"""
    PENDING = "pending"
    WAITING = "waiting"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


class PlanStatus(str, Enum):
    """计划状态枚举"""
    DRAFT = "draft"
    APPROVED = "approved"
    RUNNING = "running"
    COMPLETED = "completed"
    STOPPED = "stopped"


class UserAction(str, Enum):
    """用户操作枚举"""
    CONFIRM = "confirm"
    SKIP = "skip"
    MODIFY = "modify"
    DETAILS = "details"
    STOP = "stop"
    AUTO = "auto"


class TargetInfo(BaseModel):
    """目标信息"""
    host: str = Field(..., description="目标主机地址")
    port: Optional[int] = Field(None, description="目标端口")
    scheme: Optional[str] = Field(None, description="协议类型 (http/https)")
    target_type: str = Field(default="ip", description="目标类型 (ip/domain/url)")
    
    @classmethod
    def parse(cls, target: str) -> "TargetInfo":
        """解析目标字符串"""
        target = target.strip()
        
        # URL 格式
        if target.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            parsed = urlparse(target)
            return cls(
                host=parsed.hostname or target,
                port=parsed.port,
                scheme=parsed.scheme,
                target_type="url"
            )
        
        # IP:Port 格式
        if ":" in target and not target.startswith("["):
            parts = target.rsplit(":", 1)
            if parts[1].isdigit():
                return cls(
                    host=parts[0],
                    port=int(parts[1]),
                    target_type="ip" if cls._is_ip(parts[0]) else "domain"
                )
        
        # 纯 IP 或域名
        return cls(
            host=target,
            target_type="ip" if cls._is_ip(target) else "domain"
        )
    
    @staticmethod
    def _is_ip(s: str) -> bool:
        """检查是否为 IP 地址"""
        import re
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        ipv6_pattern = r'^\[?[0-9a-fA-F:]+\]?$'
        return bool(re.match(ipv4_pattern, s) or re.match(ipv6_pattern, s))
    
    def __str__(self) -> str:
        if self.port:
            return f"{self.host}:{self.port}"
        return self.host


class Finding(BaseModel):
    """发现结果"""
    id: str = Field(default_factory=lambda: f"finding_{datetime.now().strftime('%Y%m%d%H%M%S%f')}")
    title: str = Field(..., description="发现标题")
    description: str = Field(default="", description="详细描述")
    severity: RiskLevel = Field(default=RiskLevel.MEDIUM, description="严重程度")
    tool: str = Field(..., description="发现工具")
    raw_output: Optional[str] = Field(None, description="原始输出")
    evidence: Optional[str] = Field(None, description="证据")
    timestamp: datetime = Field(default_factory=datetime.now, description="时间戳")
    references: List[str] = Field(default_factory=list, description="参考链接")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="额外元数据")


class ToolResult(BaseModel):
    """工具执行结果"""
    success: bool = Field(..., description="是否成功")
    output: str = Field(default="", description="原始输出")
    error: Optional[str] = Field(None, description="错误信息")
    execution_time: float = Field(default=0.0, description="执行时间(秒)")
    findings: List[Finding] = Field(default_factory=list, description="发现的问题")
    parsed_data: Optional[Dict[str, Any]] = Field(None, description="解析后的数据")


class Step(BaseModel):
    """执行步骤"""
    id: str = Field(default_factory=lambda: f"step_{datetime.now().strftime('%Y%m%d%H%M%S%f')}")
    name: str = Field(..., description="步骤名称")
    tool: str = Field(..., description="使用的工具")
    command: str = Field(..., description="执行命令")
    description: str = Field(default="", description="详细说明")
    risk_level: RiskLevel = Field(default=RiskLevel.LOW, description="风险等级")
    expected_output: str = Field(default="", description="预期输出")
    dependencies: List[str] = Field(default_factory=list, description="依赖的步骤ID")
    status: StepStatus = Field(default=StepStatus.PENDING, description="步骤状态")
    result: Optional[ToolResult] = Field(None, description="执行结果")
    created_at: datetime = Field(default_factory=datetime.now, description="创建时间")
    executed_at: Optional[datetime] = Field(None, description="执行时间")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="额外元数据")


class ExecutionPlan(BaseModel):
    """执行计划"""
    id: str = Field(default_factory=lambda: f"plan_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    target: TargetInfo = Field(..., description="目标信息")
    strategy: str = Field(default="standard", description="测试策略")
    steps: List[Step] = Field(default_factory=list, description="执行步骤")
    status: PlanStatus = Field(default=PlanStatus.DRAFT, description="计划状态")
    created_at: datetime = Field(default_factory=datetime.now, description="创建时间")
    updated_at: datetime = Field(default_factory=datetime.now, description="更新时间")
    
    def get_current_step(self) -> Optional[Step]:
        """获取当前待执行的步骤"""
        for step in self.steps:
            if step.status == StepStatus.PENDING:
                return step
        return None
    
    def get_progress(self) -> tuple:
        """获取进度信息"""
        total = len(self.steps)
        completed = sum(1 for s in self.steps if s.status == StepStatus.COMPLETED)
        return completed, total
    
    def mark_step_completed(self, step_id: str, result: ToolResult) -> None:
        """标记步骤完成"""
        for step in self.steps:
            if step.id == step_id:
                step.status = StepStatus.COMPLETED
                step.result = result
                step.executed_at = datetime.now()
                break
        self.updated_at = datetime.now()
    
    def mark_step_skipped(self, step_id: str) -> None:
        """标记步骤跳过"""
        for step in self.steps:
            if step.id == step_id:
                step.status = StepStatus.SKIPPED
                break
        self.updated_at = datetime.now()


class SecurityCheckResult(BaseModel):
    """安全检查结果"""
    is_safe: bool = Field(..., description="是否安全")
    risk_level: RiskLevel = Field(default=RiskLevel.LOW, description="风险等级")
    warnings: List[str] = Field(default_factory=list, description="警告信息")
    blocked: bool = Field(default=False, description="是否被阻止")
    reason: Optional[str] = Field(None, description="原因")
