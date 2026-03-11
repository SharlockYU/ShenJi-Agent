"""
人工确认处理器 - 处理用户确认交互
"""

from typing import Optional, Tuple
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from agent.core.models import Step, UserAction, RiskLevel, SecurityCheckResult


class HumanApprovalHandler:
    """
    人工确认处理器
    负责显示步骤信息并获取用户确认
    """
    
    def __init__(self, auto_mode: bool = False, auto_threshold: RiskLevel = RiskLevel.LOW):
        self.console = Console()
        self.auto_mode = auto_mode
        self.auto_threshold = auto_threshold
        self._session_auto_mode = False
    
    def request_approval(
        self,
        step: Step,
        step_number: int,
        total_steps: int,
        security_check: Optional[SecurityCheckResult] = None
    ) -> Tuple[UserAction, Optional[str]]:
        """
        请求用户确认
        
        Args:
            step: 当前步骤
            step_number: 步骤编号
            total_steps: 总步骤数
            security_check: 安全检查结果
            
        Returns:
            (用户操作, 修改后的命令)
        """
        # 如果是自动模式且风险等级低于阈值，自动确认
        if self._should_auto_approve(step.risk_level):
            self._display_auto_approval(step, step_number, total_steps)
            return UserAction.CONFIRM, None
        
        # 显示步骤信息
        self._display_step_info(step, step_number, total_steps, security_check)
        
        # 获取用户输入
        while True:
            choice = Prompt.ask(
                "\n🤔 执行此命令？",
                choices=["y", "n", "m", "d", "s", "a"],
                default="y"
            )
            
            if choice.lower() == "y":
                return UserAction.CONFIRM, None
            
            elif choice.lower() == "n":
                return UserAction.SKIP, None
            
            elif choice.lower() == "m":
                modified_cmd = self._get_modified_command(step.command)
                if modified_cmd:
                    return UserAction.MODIFY, modified_cmd
                continue
            
            elif choice.lower() == "d":
                self._display_details(step)
                continue
            
            elif choice.lower() == "s":
                if self._confirm_stop():
                    return UserAction.STOP, None
                continue
            
            elif choice.lower() == "a":
                self._session_auto_mode = True
                return UserAction.AUTO, None
    
    def _should_auto_approve(self, risk_level: RiskLevel) -> bool:
        """判断是否应该自动批准"""
        if self.auto_mode or self._session_auto_mode:
            risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
            return risk_order.index(risk_level) <= risk_order.index(self.auto_threshold)
        return False
    
    def _display_auto_approval(self, step: Step, step_number: int, total_steps: int) -> None:
        """显示自动批准信息"""
        self.console.print(f"\n[auto] 自动批准步骤 {step_number}/{total_steps}: {step.name}")
    
    def _display_step_info(
        self,
        step: Step,
        step_number: int,
        total_steps: int,
        security_check: Optional[SecurityCheckResult]
    ) -> None:
        """显示步骤信息面板"""
        # 构建内容
        content_lines = [
            f"[bold]Step {step_number}/{total_steps}:[/] {step.name}",
            "",
            f"[cyan]命令:[/] {step.command}",
            "",
            f"[cyan]说明:[/] {step.description}",
            "",
            f"[cyan]风险:[/] {step.risk_level.get_display()}"
        ]
        
        # 添加安全检查警告
        if security_check and security_check.warnings:
            content_lines.append("")
            content_lines.append("[yellow]⚠️ 安全警告:[/]")
            for warning in security_check.warnings:
                content_lines.append(f"  • {warning}")
        
        panel = Panel(
            "\n".join(content_lines),
            title="🔒 等待确认",
            border_style="yellow"
        )
        
        self.console.print(panel)
    
    def _display_details(self, step: Step) -> None:
        """显示详细信息"""
        table = Table(title="步骤详情")
        table.add_column("属性", style="cyan")
        table.add_column("值", style="white")
        
        table.add_row("工具", step.tool)
        table.add_row("命令", step.command)
        table.add_row("说明", step.description)
        table.add_row("风险等级", step.risk_level.get_display())
        table.add_row("预期输出", step.expected_output or "无")
        table.add_row("依赖步骤", ", ".join(step.dependencies) if step.dependencies else "无")
        
        self.console.print(table)
    
    def _get_modified_command(self, original_cmd: str) -> Optional[str]:
        """获取修改后的命令"""
        self.console.print(f"\n[cyan]原始命令:[/] {original_cmd}")
        self.console.print("[dim]输入新命令（直接回车取消修改）[/]")
        
        new_cmd = Prompt.ask("新命令", default=original_cmd)
        
        if new_cmd == original_cmd:
            return None
        return new_cmd
    
    def _confirm_stop(self) -> bool:
        """确认停止"""
        return Prompt.ask(
            "⚠️ 确定要停止整个任务吗？",
            choices=["y", "n"],
            default="n"
        ).lower() == "y"
    
    def request_plan_approval(self, plan_steps: list) -> bool:
        """请求计划批准"""
        self.console.print("\n📋 [bold]执行计划:[/]")
        
        for i, step in enumerate(plan_steps, 1):
            risk_display = step.risk_level.get_display()
            self.console.print(f"  Step {i}: {step.name} - {risk_display}")
        
        return Prompt.ask(
            "\n🤔 是否批准此计划？",
            choices=["y", "n"],
            default="y"
        ).lower() == "y"
    
    def show_message(self, message: str, style: str = "info") -> None:
        """显示消息"""
        style_map = {
            "info": "[blue]ℹ️[/]",
            "success": "[green]✓[/]",
            "warning": "[yellow]⚠️[/]",
            "error": "[red]✗[/]"
        }
        self.console.print(f"{style_map.get(style, '')} {message}")
