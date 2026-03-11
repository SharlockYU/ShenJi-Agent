"""
神机 (ShenJi) - 主程序入口
支持 SmartAgent 和 传统多Agent 模式
"""

import os
import sys
import json
import re
import yaml
from typing import Optional, Dict, Any, List
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from loguru import logger

from agent.agents.coordinator import AgentCoordinator
from agent.agents.recon_agent import ReconAgent
from agent.agents.scan_agent import ScanAgent
from agent.agents.enum_agent import EnumAgent
from agent.agents.vuln_agent import VulnAgent
from agent.core.models import TargetInfo, ToolResult, ExecutionPlan, Step, RiskLevel, StepStatus, PlanStatus, UserAction, Finding, SecurityCheckResult
from agent.core.approval import HumanApprovalHandler
from agent.core.executor import ToolExecutor
from agent.tools.http import HTTPTool
from agent.tools.nmap import NmapTool
from agent.tools.nikto import NiktoTool
from agent.tools.gobuster import GobusterTool
from agent.tools.nuclei import NucleiTool
from agent.tools.base import BaseTool, ToolInfo
from agent.llm.provider import LLMProvider

from agent.agents.base import AgentRole, AgentStatus, AgentMessage, AgentTask, Decision, TaskPriority
from agent.agents.master import MasterAgent


class PentestAgent:
    """渗透测试主程序"""
    
    def __init__(
        self,
        config_path: Optional[str] = None,
        auto_mode: bool = False,
        target: Optional[str] = None
    ):
        self.console = Console()
        self.config = self._load_config(config_path)
        self.auto_mode = auto_mode
        self.target_info: Optional[TargetInfo] = None
        self.target = target
        self.strategy = "standard"  # 添加默认策略
        
        # 初始化组件
        self.approval_handler = HumanApprovalHandler(
            auto_mode=self.auto_mode,
            auto_threshold=RiskLevel.LOW
        )
        self.executor = ToolExecutor(self.config.get("tools", {}))
        self.llm_provider: Optional[LLMProvider] = None
        
        # Agent系统
        self.coordinator: Optional[AgentCoordinator] = None
        self.master: Optional[MasterAgent] = None
        self.recon_agent: Optional[ReconAgent] = None
        self.scan_agent: Optional[ScanAgent] = None
        self.enum_agent: Optional[EnumAgent] = None
        self.vuln_agent: Optional[VulnAgent] = None
        
        # 执行状态
        self._running = False
        self._task_queue: List[AgentTask] = []
        self._completed_tasks: List[AgentTask] = []
        self._findings: List[Finding] = []
        self._plan: Optional[ExecutionPlan] = None
        self._context: Dict[str, Any] = {}
        
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """加载配置文件"""
        config = {}
        
        if config_path:
            config_file = Path(config_path)
        else:
            # 尝试查找默认配置文件
            if Path("config.yaml").exists():
                config_file = Path("config.yaml")
            elif Path("config.cfg").exists():
                config_file = Path("config.cfg")
            else:
                return {}
        
        try:
            if config_file.suffix == ".yaml" or config_file.suffix == ".yml":
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f) or {}
            elif config_file.suffix == ".cfg":
                # 使用configparser解析
                import configparser
                cfg = configparser.ConfigParser()
                cfg.read(config_file, encoding='utf-8')
                
                # 转换配置格式
                config = {'tools': {}, 'llm': {}, 'agent': {}}
                for section in cfg.sections():
                    if section == 'tools':
                        for key, value in cfg[section].items():
                            config['tools'][key] = value
                    elif section == 'llm':
                        for key, value in cfg[section].items():
                            config['llm'][key] = value
                    elif section == 'agent':
                        for key, value in cfg[section].items():
                            config['agent'][key] = value
                    else:
                        config[section] = dict(cfg[section])
        except Exception as e:
            print(f"加载配置文件失败: {e}")
            return {}
        
        # 确保必要的配置项存在
        if 'tools' not in config:
            config['tools'] = {}
        if 'llm' not in config:
            config['llm'] = {}
        if 'agent' not in config:
            config['agent'] = {}
        
        return config
    
    def _show_welcome(self) -> None:
        """显示欢迎信息"""
        agent_config = self.config.get("agent", {})
        name = agent_config.get("name", "PentestAgent Multi-Agent")
        version = agent_config.get("version", "2.0.0")
        
        self.console.print(Panel(
            f"[bold cyan]{name}[/] v{version}\n\n"
            "[yellow]⚠️ 仅限合法授权场景使用[/]\n\n"
            "[dim]多Agent模式: 总指挥负责决策，工作Agent负责执行[/]",
            title="🛡️ 渗透测试 Agent",
            border_style="blue"
        ))
        
        # 显示Agent团队
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
    
    def run(self, target: str, strategy: str = "standard") -> Dict[str, Any]:
        """
        运行渗透测试
        
        Args:
            target: 目标地址
            strategy: 测试策略 (standard/recon/scan/full)
            
        Returns:
            测试结果摘要
        """
        self._running = True
        self.target = target
        self.strategy = strategy
        
        # 显示欢迎信息
        self._show_welcome()
        
        # 解析目标
        self.target_info = TargetInfo.parse(target)
        
        # 初始化Agent系统
        self._initialize_agents()
        
        # 显示目标
        self.console.print(f"\n[cyan]目标:[/] {self.target_info}")
        
        # 创建初始计划
        self._create_initial_plan()
        
        # 显示计划
        self._display_plan()
        
        # 请求用户确认
        if not self._request_plan_approval():
            self.console.print("[red]计划已取消[/]")
            return {"status": "cancelled", "reason": "user_cancelled"}
        
        # 执行任务循环
        try:
            self._execute_task_loop()
        except KeyboardInterrupt:
            self.console.print("\n[yellow]用户中断执行[/]")
            self._stop()
        
        # 显示结果
        return self._show_summary()
    
    def _initialize_agents(self) -> None:
        """初始化所有Agent"""
        self.console.print(Panel(
            "[bold cyan]正在初始化Agent系统...[/]",
            title="🤖 多Agent系统",
            border_style="blue"
        ))
        
        # 创建总指挥Agent
        self.master = MasterAgent("main", self.config)
        self.master.initialize()
        self.console.print("[green]✓[/] 总指挥Agent已就位")
        
        # 创建侦察Agent
        self.recon_agent = ReconAgent("recon_1", self.config)
        self.recon_agent.initialize()
        self.console.print("[green]✓[/] 侦察Agent已就位")
        
        # 创建扫描Agent
        self.scan_agent = ScanAgent("scan_1", self.config)
        self.scan_agent.initialize()
        self.console.print("[green]✓[/] 扫描Agent已就位")
        
        # 创建枚举Agent
        self.enum_agent = EnumAgent("enum_1", self.config)
        self.enum_agent.initialize()
        self.console.print("[green]✓[/] 枚举Agent已就位")
        
        # 创建漏洞Agent
        self.vuln_agent = VulnAgent("vuln_1", self.config)
        self.vuln_agent.initialize()
        self.console.print("[green]✓[/] 漏洞Agent已就位")
        
        self.console.print("\n[bold green]所有Agent已准备就绪！[/]\n")
    
    def _create_initial_plan(self) -> None:
        """创建初始执行计划"""
        self._plan = ExecutionPlan(
            target=self.target_info,
            strategy=self.strategy
        )
        
        # 初始化任务队列
        self._task_queue = []
        
        # 根据策略添加初始任务
        if self.strategy in ["standard", "recon"]:
            # 添加HTTP分析步骤
            http_task = AgentTask(
                id="http_1",
                name="HTTP内容获取和分析",
                tool="http",
                command=f"http_request {self.target}",
                description="使用HTTP工具获取网页内容",
                priority=TaskPriority.HIGH,
                target=self.target_info
            )
            self._task_queue.append(http_task)
        
        if self.strategy in ["standard", "scan"]:
            # 添加端口扫描任务
            scan_task = AgentTask(
                id="nmap_1",
                name="端口扫描",
                tool="nmap",
                command=f"nmap_scan {self.target}",
                description="使用nmap进行端口扫描",
                priority=TaskPriority.HIGH,
                target=self.target_info
            )
            self._task_queue.append(scan_task)
    
    def _display_plan(self) -> None:
        """显示执行计划"""
        if not self._task_queue:
            self.console.print("[yellow]没有待执行的任务[/]")
            return
        
        table = Table(title="📋 执行计划")
        table.add_column("ID", style="cyan", width=8)
        table.add_column("任务名称", style="white")
        table.add_column("工具", style="green")
        table.add_column("优先级", style="yellow")
        
        for task in self._task_queue:
            priority_str = task.priority.value if hasattr(task.priority, 'value') else task.priority
            table.add_row(
                str(task.id),
                str(task.name),
                str(task.tool),
                str(priority_str)
            )
        
        self.console.print(table)
    
    def _request_plan_approval(self) -> bool:
        """请求用户批准计划"""
        if self.auto_mode:
            return True
            
        action = Prompt.ask(
            "\n是否批准执行此计划？ (y/n)",
            choices=["y", "n"],
            default="y"
        )
        return action.lower() == "y"
    
    def _execute_task_loop(self) -> None:
        """执行任务循环"""
        while self._running and self._task_queue:
            # 获取下一个任务
            task = self._get_next_task()
            if not task:
                break
            
            # 显示任务信息
            self._display_task_info(task)
            
            # 请求任务批准
            action, modified_cmd = self._request_task_approval(task)
            
            if action == UserAction.STOP:
                self.console.print("[red]任务已停止[/]")
                self._stop()
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
            
            # 确定执行Agent
            agent = self._get_agent_for_task(task.tool)
            if not agent:
                self.console.print(f"[red]无法找到处理工具 {task.tool} 的Agent[/]")
                task.status = "failed"
                continue
            
            # 执行任务
            result = agent.execute_task(task)
            
            # 更新任务状态
            task.completed_at = datetime.now()
            if result.success:
                task.status = "completed"
                task.result = result
                self._completed_tasks.append(task)
                
                # 提取发现的问题
                if hasattr(result, 'findings') and result.findings:
                    self._findings.extend(result.findings)
                
                # 通知总指挥分析结果
                if self.master:
                    decision = self.master.analyze_and_decide(task, result)
                    self.master.display_decision(decision)
                    
                    if decision.is_complete:
                        self._complete_mission(decision)
                        break
                    
                    # 添加新任务
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
    
    def _get_agent_for_task(self, tool: str):
        """根据工具获取对应的Agent"""
        agent_map = {
            "http": self.recon_agent,
            "nmap": self.scan_agent,
            "gobuster": self.enum_agent,
            "nuclei": self.vuln_agent,
            "nikto": self.vuln_agent
        }
        return agent_map.get(tool)
    
    def _display_task_info(self, task: AgentTask) -> None:
        """显示任务信息"""
        self.console.print(f"\n[cyan]执行任务:[/] {task.name}")
        self.console.print(f"[dim]工具: {task.tool} | 优先级: {task.priority.value if hasattr(task.priority, 'value') else task.priority}[/]")
        self.console.print(f"[dim]命令: {task.command}[/]")
    
    def _request_task_approval(self, task: AgentTask) -> tuple:
        """请求任务批准"""
        if self.auto_mode:
            return UserAction.CONFIRM, ""
            
        security_check = self.executor.check_command_security(task.command)
        
        # 显示安全警告
        if security_check.warnings:
            self.console.print("[yellow]⚠️ 安全警告:[/]")
            for warning in security_check.warnings:
                self.console.print(f"  - {warning}")
        
        if security_check.blocked:
            self.console.print("[red]✗ 此命令被安全策略阻止[/]")
            return UserAction.STOP, ""
        
        action = Prompt.ask(
            "\n按 Enter 执行此任务 (s=跳过, m=修改命令, x=停止)",
            choices=["", "s", "m", "x"],
            default=""
        )
        
        if action == "s":
            return UserAction.SKIP, ""
        elif action == "m":
            new_cmd = Prompt.ask("请输入修改后的命令:", default=task.command)
            return UserAction.MODIFY, new_cmd
        elif action == "x":
            return UserAction.STOP, ""
        
        return UserAction.CONFIRM, ""
    
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
    
    def _stop(self) -> None:
        """停止执行"""
        self._running = False
        self.console.print("\n[yellow]任务已停止[/]")
    
    def _show_summary(self) -> Dict[str, Any]:
        """显示结果摘要"""
        summary = {
            "status": "completed" if not self._running else "stopped",
            "target": str(self.target_info) if self.target_info else "unknown",
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
            
            for i, finding in enumerate(self._findings):
                findings_table.add_row(
                    str(i + 1),
                    finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                    finding.title,
                    finding.tool
                )
            
            self.console.print("\n")
            self.console.print(findings_table)
        
        return summary


def run_shenji_agent(target: str, config: Dict[str, Any], auto_mode: bool = False) -> Dict[str, Any]:
    """
    运行神机 Agent (基于LangGraph)

    Args:
        target: 目标地址
        config: 配置字典
        auto_mode: 是否自动模式

    Returns:
        测试结果
    """
    from agent.smart_agent import ShenJiAgent

    agent = ShenJiAgent(config)
    return agent.run(target, auto_mode=auto_mode)


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description="神机 (ShenJi) - 智能渗透测试 Agent")
    parser.add_argument("target", help="目标地址")
    parser.add_argument("--strategy", "-s", default="standard",
                       choices=["standard", "recon", "scan", "full", "smart"],
                       help="测试策略 (smart=基于LangGraph的智能Agent)")
    parser.add_argument("--auto", "-a", action="store_true", help="自动模式")
    parser.add_argument("--config", "-c", default="config.yaml", help="配置文件路径")
    parser.add_argument("--max-attempts", "-m", type=int, default=10,
                       help="最大尝试次数 (仅smart模式)")

    args = parser.parse_args()

    # 加载配置
    config = {}
    if os.path.exists(args.config):
        with open(args.config, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

    # 根据策略选择Agent
    if args.strategy == "smart":
        # 使用神机 Agent
        config["max_attempts"] = args.max_attempts
        run_shenji_agent(args.target, config, auto_mode=args.auto)
    else:
        # 使用传统的多Agent模式
        agent = PentestAgent(
            config_path=args.config,
            auto_mode=args.auto
        )
        agent.run(args.target, args.strategy)


if __name__ == "__main__":
    main()
