"""
上下文管理器 - 管理渗透测试过程中的上下文信息
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from agent.core.models import Finding, TargetInfo, ExecutionPlan, ToolResult


class ContextManager:
    """
    上下文管理器
    负责维护渗透测试过程中的所有上下文信息
    """
    
    def __init__(self, target: TargetInfo):
        self.target = target
        self.findings: List[Finding] = []
        self.scan_results: Dict[str, ToolResult] = {}
        self.discovered_info: Dict[str, Any] = {}
        self.plan: Optional[ExecutionPlan] = None
        self.session_id = f"session_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        self._context: Dict[str, Any] = {}
    
    def add_finding(self, finding: Finding) -> None:
        """添加发现"""
        self.findings.append(finding)
    
    def add_findings(self, findings: List[Finding]) -> None:
        """批量添加发现"""
        self.findings.extend(findings)
    
    def store_result(self, step_id: str, result: ToolResult) -> None:
        """存储扫描结果"""
        self.scan_results[step_id] = result
        if result.findings:
            self.add_findings(result.findings)
    
    def update_discovered_info(self, key: str, value: Any) -> None:
        """更新发现的信息"""
        self.discovered_info[key] = value
    
    def set_plan(self, plan: ExecutionPlan) -> None:
        """设置执行计划"""
        self.plan = plan
    
    def get_context_for_llm(self) -> str:
        """
        获取用于 LLM 的上下文摘要
        """
        context_parts = [
            f"目标: {self.target}",
            f"会话ID: {self.session_id}",
            "",
            "=== 已发现的信息 ==="
        ]
        
        if self.discovered_info:
            for key, value in self.discovered_info.items():
                context_parts.append(f"- {key}: {value}")
        
        if self.findings:
            context_parts.append("")
            context_parts.append("=== 发现的问题 ===")
            for i, finding in enumerate(self.findings, 1):
                context_parts.append(f"{i}. [{finding.severity.value}] {finding.title}")
        
        if self.plan:
            completed, total = self.plan.get_progress()
            context_parts.append("")
            context_parts.append(f"=== 执行进度: {completed}/{total} ===")
        
        return "\n".join(context_parts)
    
    def get_open_ports(self) -> List[Dict[str, Any]]:
        """获取已发现的开放端口"""
        ports = []
        for result in self.scan_results.values():
            if result.parsed_data and "ports" in result.parsed_data:
                ports.extend(result.parsed_data["ports"])
        return ports
    
    def get_services(self) -> Dict[str, str]:
        """获取已发现的服务"""
        services = {}
        for result in self.scan_results.values():
            if result.parsed_data and "services" in result.parsed_data:
                services.update(result.parsed_data["services"])
        return services
    
    def set(self, key: str, value: Any) -> None:
        """设置自定义上下文"""
        self._context[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取自定义上下文"""
        return self._context.get(key, default)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "session_id": self.session_id,
            "target": str(self.target),
            "findings_count": len(self.findings),
            "findings": [f.model_dump() for f in self.findings],
            "discovered_info": self.discovered_info,
            "plan_id": self.plan.id if self.plan else None,
            "plan_status": self.plan.status.value if self.plan else None,
        }
