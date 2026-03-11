"""
总指挥Agent - 负责决策和任务分配
"""

import json
import re
from typing import Optional, List, Dict, Any
from datetime import datetime
from rich.panel import Panel
from rich.table import Table

from agent.agents.base import (
    BaseAgent, AgentRole, AgentStatus, AgentMessage, 
    AgentTask, Decision, TaskPriority
)
from agent.core.models import TargetInfo, ToolResult
from agent.llm.provider import LLMProvider


class MasterAgent(BaseAgent):
    """
    总指挥Agent
    
    职责：
    1. 分析目标信息
    2. 制定整体策略和决策
    3. 分配任务给工作Agent
    4. 分析执行结果
    5. 决定下一步行动
    6. 判断任务是否完成
    """
    
    def __init__(
        self,
        agent_id: str = "main",
        config: Optional[Dict[str, Any]] = None
    ):
        super().__init__(agent_id, AgentRole.MASTER, config)
        self.llm_provider: Optional[LLMProvider] = None
        self._decisions: List[Decision] = []
        self._context: Dict[str, Any] = {}  # 全局上下文
        self._findings: List[Dict[str, Any]] = []  # 发现的结果
        
    def initialize(self) -> bool:
        """初始化LLM"""
        try:
            llm_config = self.config.get("llm", {})
            self.llm_provider = LLMProvider(llm_config)
            self.llm_provider.initialize()
            self._log("LLM初始化成功", "success")
            return True
        except Exception as e:
            self._log(f"LLM初始化失败: {e}", "error")
            return False
    
    def handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理收到的消息"""
        if message.message_type == "task_completed":
            # 工作Agent完成任务报告
            return self._handle_task_completion(message)
        elif message.message_type == "task_failed":
            # 任务失败报告
            return self._handle_task_failure(message)
        elif message.message_type == "finding_report":
            # 发现报告
            return self._handle_finding(message)
        elif message.message_type == "request_decision":
            # 请求决策
            return self._handle_decision_request(message)
        return None
    
    def _handle_task_completion(self, message: AgentMessage) -> AgentMessage:
        """处理任务完成报告"""
        task = message.content.get("task")
        result = message.content.get("result")
        
        if task and result:
            # 更新上下文
            self._context[f"task_{task.id}_result"] = result
            self._log(f"收到任务完成报告: {task.name}", "success")
            
            # 分析结果并做出新决策
            decision = self.analyze_and_decide(task, result)
            
            if decision.is_complete:
                return AgentMessage(
                    from_agent=self.name,
                    to_agent="coordinator",
                    message_type="mission_complete",
                    content={
                        "reason": decision.complete_reason,
                        "flag_found": decision.flag_found,
                        "flag_value": decision.flag_value
                    }
                )
            else:
                return AgentMessage(
                    from_agent=self.name,
                    to_agent="coordinator",
                    message_type="new_tasks",
                    content={
                        "tasks": [t.dict() for t in decision.tasks],
                        "reasoning": decision.reasoning
                    }
                )
        return None
    
    def _handle_task_failure(self, message: AgentMessage) -> AgentMessage:
        """处理任务失败报告"""
        task = message.content.get("task")
        error = message.content.get("error")
        self._log(f"任务失败: {task.name} - {error}", "error")
        
        # 决定是否重试或跳过
        decision = self._make_failure_decision(task, error)
        return AgentMessage(
            from_agent=self.name,
            to_agent="coordinator",
            message_type="failure_decision",
            content={"decision": decision}
        )
    
    def _handle_finding(self, message: AgentMessage) -> AgentMessage:
        """处理发现报告"""
        finding = message.content.get("finding")
        self._findings.append(finding)
        self._log(f"收到发现: {finding.get('title', 'Unknown')}", "warning")
        return None
    
    def _handle_decision_request(self, message: AgentMessage) -> AgentMessage:
        """处理决策请求"""
        context = message.content.get("context", {})
        decision = self.make_decision(context)
        return AgentMessage(
            from_agent=self.name,
            to_agent=message.from_agent,
            message_type="decision_response",
            content={"decision": decision.dict()}
        )
    
    def analyze_and_decide(self, task: AgentTask, result: ToolResult) -> Decision:
        """
        分析任务结果并做出决策
        
        Args:
            task: 完成的任务
            result: 执行结果
            
        Returns:
            Decision: 新的决策
        """
        self.status = AgentStatus.WORKING
        
        # 首先检查结果中是否直接包含flag
        if result.output:
            flag = self._extract_flag(result.output)
            if flag:
                self._log(f"🚩 FLAG 已找到！{flag}", "success")
                decision = Decision(
                    reasoning="在任务输出中直接发现FLAG",
                    action="complete",
                    is_complete=True,
                    complete_reason="FLAG已找到",
                    flag_found=True,
                    flag_value=flag
                )
                self._decisions.append(decision)
                return decision
        
        # 检查解析数据中的flag
        if result.parsed_data:
            flag = self._check_parsed_data_for_flag(result.parsed_data)
            if flag:
                decision = Decision(
                    reasoning="在解析数据中发现FLAG",
                    action="complete",
                    is_complete=True,
                    complete_reason="FLAG已找到",
                    flag_found=True,
                    flag_value=flag
                )
                self._decisions.append(decision)
                return decision
        
        # 使用LLM分析结果并决策
        if self.llm_provider:
            decision = self._llm_analyze_and_decide(task, result)
        else:
            decision = self._rule_based_decide(task, result)
        
        self._decisions.append(decision)
        self.status = AgentStatus.IDLE
        return decision
    
    def _llm_analyze_and_decide(self, task: AgentTask, result: ToolResult) -> Decision:
        """使用LLM分析结果并做出决策"""
        prompt = self._build_decision_prompt(task, result)
        
        try:
            response = self.llm_provider.generate(prompt)
            return self._parse_llm_decision(response, task)
        except Exception as e:
            self._log(f"LLM决策失败: {e}", "error")
            return self._rule_based_decide(task, result)
    
    def _build_decision_prompt(self, task: AgentTask, result: ToolResult) -> str:
        """构建决策提示"""
        # 获取可用工具描述
        tools_desc = self._get_tools_description()
        
        # 获取历史上下文
        context_summary = self._get_context_summary()
        
        prompt = f"""【重要任务】你是渗透测试总指挥官，需要分析任务执行结果并决定下一步行动。

=== 当前任务信息 ===
任务名称: {task.name}
使用工具: {task.tool}
目标: {task.target}
执行状态: {'成功' if result.success else '失败'}

=== 执行结果 ===
输出摘要:
{result.output[:3000] if result.output else '无输出'}

错误信息: {result.error or '无'}

解析数据: {result.parsed_data or '无'}

=== 历史上下文 ===
{context_summary}

=== 可用工具和Agent ===
{tools_desc}

【请分析结果并做出决策，以JSON格式返回】：

1. 首先检查是否找到FLAG（格式如 flag{{...}}, FLAG{{...}}, ctf{{...}}）
2. 分析发现了什么有价值的信息
3. 决定是否需要进一步测试
4. 如果需要，选择合适的工具和Agent

【必须严格按照以下JSON格式返回】：
```json
{{
    "flag_found": false,
    "flag_value": "",
    "reasoning": "分析推理过程（2-3句话）",
    "action": "continue|complete|retry|skip",
    "is_complete": false,
    "complete_reason": "",
    "new_tasks": [
        {{
            "name": "任务名称",
            "description": "任务描述",
            "tool": "工具名称",
            "command": "执行命令",
            "assigned_agent": "recon|scan|enum|vuln",
            "priority": 1-5,
            "reason": "选择原因"
        }}
    ],
    "confidence": 0.8
}}
```

注意：
1. 如果找到FLAG，设置flag_found=true并填写flag_value
2. 如果认为测试完成，设置is_complete=true
3. priority越小越优先（1最高，5最低）
4. 根据工具类型选择合适的agent：
   - http/侦察类 → recon
   - nmap端口扫描 → scan
   - gobuster目录枚举 → enum
   - nuclei/nikto漏洞扫描 → vuln
"""
        return prompt
    
    def _parse_llm_decision(self, response: str, task: AgentTask) -> Decision:
        """解析LLM的决策响应"""
        try:
            # 提取JSON
            json_match = re.search(r'```json\s*([\s\S]*?)\s*```', response)
            if json_match:
                json_str = json_match.group(1)
            else:
                json_str = response.strip()
            
            data = json.loads(json_str)
            
            # 构建任务列表
            new_tasks = []
            for task_data in data.get("new_tasks", []):
                new_task = AgentTask(
                    name=task_data.get("name", "未命名任务"),
                    description=task_data.get("description", ""),
                    target=task.target,
                    tool=task_data.get("tool", ""),
                    command=task_data.get("command", ""),
                    priority=TaskPriority(task_data.get("priority", 3)),
                    context={"reason": task_data.get("reason", "")}
                )
                new_tasks.append(new_task)
            
            return Decision(
                reasoning=data.get("reasoning", ""),
                action=data.get("action", "continue"),
                tasks=new_tasks,
                is_complete=data.get("is_complete", False),
                complete_reason=data.get("complete_reason", ""),
                flag_found=data.get("flag_found", False),
                flag_value=data.get("flag_value", ""),
                confidence=data.get("confidence", 0.8)
            )
            
        except Exception as e:
            self._log(f"解析LLM决策失败: {e}", "error")
            return self._rule_based_decide(task, task.result)
    
    def _rule_based_decide(self, task: AgentTask, result: ToolResult) -> Decision:
        """基于规则的决策（LLM不可用时的后备方案）"""
        new_tasks = []
        reasoning = ""
        
        if not result.success:
            return Decision(
                reasoning=f"任务执行失败: {result.error}",
                action="skip",
                is_complete=False,
                tasks=[]
            )
        
        # 根据工具类型决定下一步
        if task.tool == "http":
            # HTTP分析后，通常需要进行端口扫描和目录枚举
            new_tasks.append(AgentTask(
                name="Nmap端口扫描",
                description="扫描目标开放端口",
                target=task.target,
                tool="nmap",
                command=f"nmap -sV -sC {task.target.host}",
                priority=TaskPriority.HIGH
            ))
            new_tasks.append(AgentTask(
                name="Gobuster目录枚举",
                description="枚举Web目录",
                target=task.target,
                tool="gobuster",
                command=f"gobuster dir -u http://{task.target.host} -w ./data/wordlists/common.txt",
                priority=TaskPriority.MEDIUM
            ))
            reasoning = "HTTP分析完成，需要进行端口扫描和目录枚举"
        
        elif task.tool == "nmap":
            # 端口扫描后，进行漏洞扫描
            new_tasks.append(AgentTask(
                name="Nuclei漏洞扫描",
                description="扫描已知漏洞",
                target=task.target,
                tool="nuclei",
                command=f"nuclei -u http://{task.target.host} -severity medium,high,critical",
                priority=TaskPriority.MEDIUM
            ))
            reasoning = "端口扫描完成，进行漏洞扫描"
        
        else:
            reasoning = "已完成主要测试任务"
        
        return Decision(
            reasoning=reasoning,
            action="continue" if new_tasks else "complete",
            tasks=new_tasks,
            is_complete=len(new_tasks) == 0
        )
    
    def make_decision(self, context: Dict[str, Any]) -> Decision:
        """基于上下文做出决策"""
        target = context.get("target")
        available_info = context.get("available_info", {})
        
        if target:
            # 初始决策 - 创建HTTP分析任务
            target_info = TargetInfo.parse(target) if isinstance(target, str) else target
            
            initial_task = AgentTask(
                name="HTTP内容分析",
                description="获取并分析网页内容",
                target=target_info,
                tool="http",
                command=f"http_request {target}",
                priority=TaskPriority.CRITICAL
            )
            
            return Decision(
                reasoning="初始侦察：首先进行HTTP内容分析",
                action="start",
                tasks=[initial_task],
                is_complete=False
            )
        
        return Decision(
            reasoning="等待更多信息",
            action="wait",
            tasks=[],
            is_complete=False
        )
    
    def _make_failure_decision(self, task: AgentTask, error: str) -> Dict[str, Any]:
        """针对失败任务做出决策"""
        # 简单规则：对于失败的任务，根据类型决定是否重试
        if task.tool in ["nmap", "gobuster"]:
            return {
                "action": "retry",
                "max_retries": 1,
                "reason": "网络工具可能因临时问题失败"
            }
        return {
            "action": "skip",
            "reason": f"任务失败: {error}"
        }
    
    def _extract_flag(self, text: str) -> Optional[str]:
        """从文本中提取flag"""
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'key\{[^}]+\}',
            r'KEY\{[^}]+\}',
        ]
        
        for pattern in flag_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None
    
    def _check_parsed_data_for_flag(self, data: Dict[str, Any]) -> Optional[str]:
        """检查解析数据中的flag"""
        if isinstance(data, dict):
            # 检查flags_found字段
            if data.get("flags_found"):
                flags = data["flags_found"]
                if isinstance(flags, list) and flags:
                    return flags[0]
                elif isinstance(flags, str):
                    return flags
            
            # 递归检查
            for value in data.values():
                if isinstance(value, str):
                    flag = self._extract_flag(value)
                    if flag:
                        return flag
                elif isinstance(value, dict):
                    flag = self._check_parsed_data_for_flag(value)
                    if flag:
                        return flag
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            flag = self._extract_flag(item)
                            if flag:
                                return flag
        return None
    
    def _get_tools_description(self) -> str:
        """获取工具描述"""
        return """
### 侦察Agent (recon)
- http: HTTP请求和网页内容分析

### 扫描Agent (scan)
- nmap: 网络端口扫描和服务检测

### 枚举Agent (enum)
- gobuster: 目录和文件枚举

### 漏洞Agent (vuln)
- nuclei: 基于模板的漏洞扫描
- nikto: Web服务器漏洞扫描
"""
    
    def _get_context_summary(self) -> str:
        """获取上下文摘要"""
        summary_parts = []
        
        if self._findings:
            summary_parts.append(f"已发现问题: {len(self._findings)}个")
        
        if self._decisions:
            summary_parts.append(f"已做决策: {len(self._decisions)}个")
        
        return "\n".join(summary_parts) if summary_parts else "暂无历史信息"
    
    def execute_task(self, task: AgentTask) -> ToolResult:
        """总指挥不直接执行任务，而是分配给工作Agent"""
        self._log("总指挥Agent不执行具体任务", "warning")
        return ToolResult(
            success=False,
            error="MasterAgent不执行具体任务"
        )
    
    def get_capabilities(self) -> Dict[str, Any]:
        """获取能力描述"""
        return {
            "agent_id": self.agent_id,
            "role": self.role.value,
            "status": self.status.value,
            "capabilities": [
                "决策制定",
                "任务分配",
                "结果分析",
                "策略规划"
            ],
            "tools": ["llm"],
            "description": "总指挥Agent - 负责整体决策和任务协调"
        }
    
    def display_decision(self, decision: Decision) -> None:
        """显示决策信息"""
        # 决策面板
        panel_content = f"[bold]推理过程:[/]\n{decision.reasoning}\n\n"
        panel_content += f"[bold]动作:[/] {decision.action}\n"
        panel_content += f"[bold]置信度:[/] {decision.confidence:.0%}"
        
        if decision.flag_found:
            panel_content += f"\n\n[green bold]🚩 FLAG: {decision.flag_value}[/]"
        
        self.console.print(Panel(
            panel_content,
            title=f"🎯 总指挥决策",
            border_style="blue"
        ))
        
        # 显示新任务
        if decision.tasks:
            table = Table(title="📋 新分配的任务")
            table.add_column("优先级", style="cyan", width=6)
            table.add_column("任务名称", style="white")
            table.add_column("工具", style="green")
            table.add_column("目标Agent", style="yellow")
            
            for task in decision.tasks:
                table.add_row(
                    str(task.priority.value),
                    task.name,
                    task.tool,
                    task.assigned_to or "待分配"
                )
            
            self.console.print(table)
