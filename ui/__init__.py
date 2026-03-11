"""
UI 模块 - 终端界面组件
"""

from typing import Any
from rich.console import Console
from rich.progress import Progress
from rich.table import Table


class UI:
    """终端 UI 模块"""
    
    def __init__(self):
        self.console = Console()
    
    def show_welcome(self) -> None:
        """显示欢迎信息"""
        self.console.print("""
┌─────────────────────────────────────────────────────────────┐
│  🛡️ PentestAgent v1.0                                  │
│  基于 LLM 的渗透测试自动化辅助系统                    │
│  支持人工确认的交互式执行                              │
└─────────────────────────────────────────────────────────────┘
        """)
    
    def show_plan(self, plan: Any) -> None:
        """显示执行计划"""
        table = Table(title="📋 执行计划")
        table.add_column("#", style="cyan", width=4)
        table.add_column("步骤名称", style="white")
        table.add_column("工具", style="green")
        table.add_column("风险", style="yellow")
        
        for i in range(len(plan.steps)):
            step = plan.steps[i]
            table.add_row(
                str(i + 1),
                step.name,
                step.tool,
                step.risk_level.get_display()
            )
        
        self.console.print(table)
    
    def show_step(self, step: Any, step_number: int, total_steps: int) -> None:
        """显示步骤信息"""
        self.console.print(f"\n[bold]Step {step_number}/{total_steps}:[/] {step.name}")
        self.console.print(f"[dim]命令: {step.command}[/]")
    
    def show_progress_spinner(self, text: str) -> None:
        """显示进度旋转器"""
        with Progress(transient=True) as progress:
            progress.add_task(f"[cyan]{text}...", total=None)
    
    def show_result(self, title: str, result: str) -> None:
        """显示结果"""
        self.console.print(f"\n[green]✓ {title}[/]")
        self.console.print(result)
    
    def show_summary(self, data: dict) -> None:
        """显示摘要"""
        table = Table(title="📊 测试结果摘要")
        table.add_column("项目", style="cyan")
        table.add_column("值", style="white")
        
        for key, value in data.items():
            table.add_row(key, str(value))
        
        self.console.print(table)
    
    def show_error(self, message: str) -> None:
        """显示错误"""
        self.console.print(f"[red]✗ {message}[/]")
    
    def show_warning(self, message: str) -> None:
        """显示警告"""
        self.console.print(f"[yellow]⚠️ {message}[/]")
