"""
Agent协调器 - 负责协调所有Agent的工作
"""

import time
from typing import Optional, List, Dict, Any
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live

from agent.agents.base import (
    BaseAgent, AgentRole, AgentStatus, AgentMessage, AgentTask, Decision, TaskPriority
)
from agent.agents.master import MasterAgent
from agent.agents.recon_agent import ReconAgent
from agent.agents.scan_agent import ScanAgent
from agent.agents.enum_agent import EnumAgent
from agent.agents.vuln_agent import VulnAgent
from agent.core.models import TargetInfo, ToolResult


from agent.core.approval import HumanApprovalHandler
from agent.core.models import RiskLevel, UserAction


from loguru import logger


class AgentCoordinator:
    """
    Agent协调器
    
    职责：
    1. 管理所有Agent的生命周期
    2. 协调Agent之间的消息传递
    3. 分配任务给合适的工作Agent
    4. 收集和汇总结果
    5. 向用户展示进度和结果
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.console = Console()
        
        # Agent实例
        self.master: Optional[MasterAgent] = None
        self.recon_agent: Optional[ReconAgent] = None
        self.scan_agent: Optional[ScanAgent] = None
        self.enum_agent: Optional[EnumAgent] = None
        self.vuln_agent: Optional[VulnAgent] = None
        
        # 状态
        self._running = False
        self._target: Optional[TargetInfo] = None
        self._task_queue: List[AgentTask] = []
        self._completed_tasks: List[AgentTask] = []
        self._findings: List[Dict[str, Any]] = []
        self._messages: List[AgentMessage] = []
        
        # 用户批准处理器
        self.approval_handler = HumanApprovalHandler(
            auto_mode=self.config.get("auto_mode", False),
            auto_threshold=RiskLevel.LOW
        )
    
    def initialize_agents(self) -> None:
        """初始化所有Agent"""
        self.console.print(Panel(
            "[bold cyan]正在初始化Agent系统...[/]",
            title="🤖 多Agent系统",
            border_style="blue"
        ))
        
        # 创建总指挥Agent
        self.master = MasterAgent("main", self.config)
        self.master.initialize()
        self.master.set_message_handler(self._handle_message)
        self.console.print("[green]✓[/] 总指挥Agent已就位")
        
        # 创建侦察Agent
        self.recon_agent = ReconAgent("1", self.config)
        self.recon_agent.set_message_handler(self._handle_message)
        self.console.print("[green]✓[/] 侦察Agent已就位")
        
        # 创建扫描Agent
        self.scan_agent = ScanAgent("1", self.config)
        self.scan_agent.set_message_handler(self._handle_message)
        self.console.print("[green]✓[/] 扫描Agent已就位")
        
        # 创建枚举Agent
        self.enum_agent = EnumAgent("1", self.config)
        self.enum_agent.set_message_handler(self._handle_message)
        self.console.print("[green]✓[/] 枚举Agent已就位")
        
        # 创建漏洞Agent
        self.vuln_agent = VulnAgent("1", self.config)
        self.vuln_agent.set_message_handler(self._handle_message)
        self.console.print("[green]✓[/] 漏洞Agent已就位")
        
        self.console.print("\n[bold green]所有Agent已准备就绪！[/]\n")
    
    def _handle_message(self, message: AgentMessage) -> None:
        """处理Agent消息"""
        self._messages.append(message)
        
        # 路由消息
        if message.message_type == "task_completed":
            self._handle_task_completed(message)
        elif message.message_type == "task_failed":
            self._handle_task_failed(message)
        elif message.message_type == "finding_report":
            self._handle_finding(message)
        elif message.message_type == "new_tasks":
            self._handle_new_tasks(message)
        elif message.message_type == "mission_complete":
            self._handle_mission_complete(message)
        elif message.message_type == "task_accepted":
            self._handle_task_accepted(message)
    
    def _handle_task_completed(self, message: AgentMessage) -> None:
        """处理任务完成"""
        task_data = message.content.get("task")
        result_data = message.content.get("result")
        
        self.console.print(f"[green]✓[/] 任务完成: {task_data.get('name', 'Unknown')}")
        
        # 通知总指挥分析结果
        if self.master and task_data and result_data:
            task = AgentTask(**task_data) if isinstance(task_data, dict) else task_data
            result = ToolResult(**result_data) if isinstance(result_data, dict) else result_data
            
            self._completed_tasks.append(task)
            
            # 总指挥分析并决策
            decision = self.master.analyze_and_decide(task, result)
            self.master.display_decision(decision)
            
            if decision.is_complete:
                self._complete_mission(decision)
            elif decision.tasks:
                # 添加新任务到队列
                for new_task in decision.tasks:
                    self._task_queue.append(new_task)
    
    def _handle_task_failed(self, message: AgentMessage) -> None:
        """处理任务失败"""
        task_data = message.content.get("task")
        error = message.content.get("error")
        
        self.console.print(f"[red]✗[/] 任务失败: {task_data.get('name', 'Unknown')} - {error}")
        
        # 通知总指挥
        if self.master:
            task = AgentTask(**task_data) if isinstance(task_data, dict) else task_data
            decision = self.master._make_failure_decision(task, error)
            self.console.print(f"[yellow]总指挥决策: {decision.get('action', 'unknown')}[/]")
    
    def _handle_finding(self, message: AgentMessage) -> None:
        """处理发现报告"""
        finding = message.content.get("finding")
        self._findings.append(finding)
        self.console.print(f"[yellow]🔍 发现: {finding.get('title', 'Unknown')}[/]")
    
    def _handle_new_tasks(self, message: AgentMessage) -> None:
        """处理新任务"""
        tasks_data = message.content.get("tasks", [])
        reasoning = message.content.get("reasoning", "")
        
        self.console.print(f"[cyan]📋 总指挥分配了 {len(tasks_data)} 个新任务[/]")
        self.console.print(f"[dim]原因: {reasoning}[/]")
        
        # 将任务添加到队列
        for task_data in tasks_data:
            task = AgentTask(**task_data)
            self._task_queue.append(task)
    
    def _handle_mission_complete(self, message: AgentMessage) -> None:
        """处理任务完成"""
        reason = message.content.get("reason", "")
        flag_found = message.content.get("flag_found", False)
        flag_value = message.content.get("flag_value", "")
        
        self._running = False
        
        if flag_found and flag_value:
            self.console.print(f"\n[green bold]🚩🚩🚩 FLAG 已找到！🚩🚩🚩[/]")
            self.console.print(Panel(
                flag_value,
                title="🚩 FLAG",
                border_style="green",
                style="bold green"
            ))
        else:
            self.console.print(f"\n[green]✓ 任务完成: {reason}[/]")
    
    def _handle_task_accepted(self, message: AgentMessage) -> None:
        """处理任务接受"""
        task_id = message.content.get("task_id")
        self.console.print(f"[dim]任务已接受: {task_id}[/]")
    
    def run(self, target: str) -> Dict[str, Any]:
        """
        运行多Agent系统
        
        Args:
            target: 目标地址
            
        Returns:
            测试结果摘要
        """
        self._running = True
        self._target = TargetInfo.parse(target)
        
        # 初始化Agent
        self.initialize_agents()
        
        # 显示欢迎信息
        self._show_welcome()
        
        # 显示目标
        self.console.print(f"\n[cyan]目标:[/] {self._target}")
        
        # 请求总指挥做出初始决策
        self.console.print("\n[yellow]总指挥正在制定初始计划...[/]")
        initial_decision = self.master.make_decision({
            "target": target,
            "available_info": {}
        })
        
        self.master.display_decision(initial_decision)
        
        # 将初始任务添加到队列
        if initial_decision.tasks:
            for task in initial_decision.tasks:
                self._task_queue.append(task)
        
        # 请求用户确认计划
        if not self._request_plan_approval():
            self.console.print("[red]计划已取消[/]")
            return {"status": "cancelled", "reason": "user_cancelled"}
        
        # 执行任务循环
        try:
            self._execute_tasks()
        except KeyboardInterrupt:
            self.console.print("\n[yellow]用户中断执行[/]")
        except Exception as e:
            logger.exception("执行过程中发生错误")
            self.console.print(f"[red]错误: {e}[/]")
        
        # 显示结果摘要
        return self._show_summary()
    
    def _show_welcome(self) -> None:
        """显示欢迎信息"""
        agent_config = self.config.get("agent", {})
        name = agent_config.get("name", "PentestAgent Multi-Agent")
        version = agent_config.get("version", "2.0.0")
        
        self.console.print(Panel(
            f"[bold cyan]{name}[/] v{version}\n\n"
            "[yellow]⚠️ 仅限合法授权场景使用[/]\n\n"
            "[dim]多Agent模式: 总指挥负责决策， 工作Agent负责执行[/]",
            title="🛡️ 渗透测试 Agent",
            border_style="blue"
        ))
        
        # 显示Agent信息
        table = Table(title="🤖 Agent团队")
        table.add_column("角色", style="cyan")
        table.add_column("职责", style="white")
        table.add_column("工具", style="green")
        
        table.add_row("总指挥", "决策、任务分配", "LLM")
        table.add_row("侦察", "HTTP分析", "http")
        table.add_row("扫描", "端口扫描", "nmap")
        table.add_row("枚举", "目录枚举", "gobuster")
        table.add_row("漏洞", "漏洞扫描", "nuclei, nikto")
        
        self.console.print(table)
    
    def _request_plan_approval(self) -> bool:
        """请求用户批准计划"""
        if not self._task_queue:
            return True
        
        # 显示计划
        table = Table(title="📋 执行计划")
        table.add_column("#", style="cyan", width=4)
        table.add_column("任务名称", style="white")
        table.add_column("工具", style="green")
        table.add_column("目标Agent", style="yellow")
        table.add_column("优先级", style="magenta")
        
        for i in range(len(self._task_queue)):
            task = self._task_queue[i]
            assigned_agent = self._get_agent_for_tool(task.tool)
            table.add_row(
                str(i + 1),
                task.name,
                task.tool,
                assigned_agent.value if assigned_agent else "待分配",
                str(task.priority.value)
            )
        
        self.console.print(table)
        
        # 请求确认
        from rich.prompt import Prompt
        action = Prompt.ask(
            "\n是否批准执行此计划？ (y/n)",
            choices=["y", "n"],
            default="y"
        )
        
        return action.lower() == "y"
    
    def _get_agent_for_tool(self, tool: str) -> Optional[AgentRole]:
        """根据工具获取对应的Agent角色"""
        tool_agent_map = {
            "http": AgentRole.RECON,
            "nmap": AgentRole.SCAN,
            "gobuster": AgentRole.ENUM,
            "nuclei": AgentRole.VULN,
            "nikto": AgentRole.VULN
 }
        return tool_agent_map.get(tool)
    
    def _execute_tasks(self) -> None:
        """执行任务循环"""
        while self._running and self._task_queue:
            # 获取下一个待执行任务
            task = self._get_next_task()
            if not task:
                # 没有更多任务
                break
            
            # 确定目标Agent
            target_agent = self._get_agent_for_task(task.tool)
            agent = self._get_agent_by_role(target_agent)
            
            if not agent:
                self.console.print(f"[red]无法找到处理工具 {task.tool} 的Agent[/]")
                continue
            
            # 显示任务信息
            self._display_task_info(task, target_agent)
            
            # 请求用户批准
            action, modified_cmd = self._request_task_approval(task)
            
            if action == UserAction.STOP:
                self.console.print("[red]任务已停止[/]")
                break
            
            if action == UserAction.SKIP:
                self.console.print("[yellow]任务已跳过[/]")
                task.status = "skipped"
                continue
            
            if action == UserAction.MODIFY and modified_cmd:
                task.command = modified_cmd
                self.console.print(f"[cyan]使用修改后的命令:[/] {modified_cmd}")
            
            # 执行任务
            task.status = "running"
            task.started_at = datetime.now()
            
            result = agent.execute_task(task)
            
            # 更新任务状态
            if result.success:
                task.status = "completed"
                task.result = result
                task.completed_at = datetime.now()
                self._completed_tasks.append(task)
                
                # 通知总指挥分析结果
                decision = self.master.analyze_and_decide(task, result)
                self.master.display_decision(decision)
                
                if decision.is_complete:
                    self._complete_mission(decision)
                    break
                
                if decision.tasks:
                    for new_task in decision.tasks:
                        self._task_queue.append(new_task)
            else:
                task.status = "failed"
                self.console.print(f"[red]✗ 任务失败: {result.error}[/]")
    
    def _get_next_task(self) -> Optional[AgentTask]:
        """获取下一个待执行任务"""
        for task in self._task_queue:
            if task.status == "pending":
                return task
        return None
    
    def _get_agent_by_role(self, role: AgentRole) -> Optional[BaseAgent]:
        """根据角色获取Agent"""
        agent_map = {
            AgentRole.MASTER: self.master,
            AgentRole.RECON: self.recon_agent,
            AgentRole.SCAN: self.scan_agent,
            AgentRole.ENUM: self.enum_agent,
            AgentRole.VULN: self.vuln_agent,
        }
        return agent_map.get(role)
    
    def _display_task_info(self, task: AgentTask, role: AgentRole) -> None:
        """显示任务信息"""
        self.console.print(f"\n[cyan]执行任务:[/] {task.name}")
        self.console.print(f"[dim]工具: {task.tool} | Agent: {role.value}[/]")
        self.console.print(f"[dim]命令: {task.command}[/]")
    
    def _request_task_approval(self, task: AgentTask) -> tuple:
        """请求任务批准"""
        security_check = self._get_security_check(task.command)
        
        from rich.prompt import Prompt
        
        # 显示安全警告
        if security_check.warnings:
            self.console.print(f"[yellow]⚠️ 安全警告:[/]")
            for warning in security_check.warnings:
                self.console.print(f"  - {warning}")
        
        if security_check.blocked:
            self.console.print(f"[red]✗ 此命令被安全策略阻止[/]")
            return UserAction.STOP, None
        
        action = Prompt.ask(
            "\n按 Enter 执行此任务 (s=跳过, m=修改命令, x=停止)",
            choices=["Enter", "s", "m", "x"],
            default="Enter"
        )
        
        if action == "s":
            return UserAction.SKIP, None
        elif action == "m":
            new_cmd = Prompt.ask("请输入修改后的命令:", default=task.command)
            # 检查修改后的命令
            security_check = self._get_security_check(new_cmd)
            if security_check.blocked:
                self.console.print(f"[red]修改后的命令被阻止，请重新输入[/]")
                return self._request_task_approval(task)
            return UserAction.MODIFY, new_cmd
        elif action == "x":
            return UserAction.STOP, None
        
        return UserAction.CONFIRM, None
    
    def _get_security_check(self, command: str):
        """获取安全检查结果"""
        from agent.core.executor import ToolExecutor
        executor = ToolExecutor(self.config.get("tools", {}))
        return executor.check_command_security(command)
    
    def _complete_mission(self, decision: Decision) -> None:
        """完成任务"""
        self._running = False
        
        if decision.flag_found:
            self.console.print(f"\n[green bold]🚩🚩🚩 FLAG 已找到！🚩🚩🚩[/]")
            self.console.print(Panel(
                decision.flag_value,
                title="🚩 FLAG",
                border_style="green",
                style="bold green"
            ))
        else:
            self.console.print(f"\n[green]✓ 任务完成[/]")
            self.console.print(f"[dim]原因: {decision.complete_reason}[/]")
    
    def _show_summary(self) -> Dict[str, Any]:
        """显示结果摘要"""
        summary = {
            "status": "completed" if not self._running else "stopped",
            "target": str(self._target) if self._target else "unknown",
            "total_tasks": len(self._completed_tasks),
            "findings_count": len(self._findings),
        }
        
        # 显示摘要面板
        table = Table(title="📊 测试结果摘要")
        table.add_column("项目", style="cyan")
        table.add_column("值", style="white")
        
        table.add_row("状态", summary["status"])
        table.add_row("目标", summary["target"])
        table.add_row("完成任务", str(summary["total_tasks"]))
        table.add_row("发现问题", str(summary["findings_count"]))
        
        self.console.print("\n")
        self.console.print(table)
        
        # 显示发现的问题
        if self._findings:
            findings_table = Table(title="🔍 发现的问题")
            findings_table.add_column("#", width=4)
            findings_table.add_column("严重程度", style="yellow")
            findings_table.add_column("标题", style="white")
            findings_table.add_column("来源工具", style="green")
            
            for i in range(len(self._findings)):
                finding = self._findings[i]
                findings_table.add_row(
                    str(i + 1),
                    finding.get("severity", "unknown"),
                    finding.get("title", "Unknown"),
                    finding.get("tool", "unknown")
                )
            
            self.console.print("\n")
            self.console.print(findings_table)
        
        return summary
