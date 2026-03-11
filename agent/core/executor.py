"""
工具执行器 - 负责执行系统命令和安全检查
"""

import subprocess
import time
import re
import shutil
from typing import Optional, Dict, Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from agent.core.models import ToolResult, Finding, RiskLevel, SecurityCheckResult


class ToolExecutor:
    """
    工具执行器
    负责执行系统命令、显示进度、捕获输出
    """
    
    # 高风险命令模式
    HIGH_RISK_PATTERNS = [
        r"rm\s+-rf",
        r"dd\s+if=",
        r"mkfs",
        r":\(\)\s*\{\s*:\|\:&\s*\}",  # Fork bomb
        r">\s*/dev/sd",
        r"chmod\s+777",
        r"chown\s+root",
        r"shutdown",
        r"reboot",
        r"init\s+0",
    ]
    
    # 禁止的命令
    BLOCKED_COMMANDS = [
        "format",
        "del /",
        "rm -rf /",
        ":(){ :|:& };:",
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.console = Console()
        self.config = config or {}
        self._check_tool_availability()
    
    def _check_tool_availability(self) -> None:
        """检查工具可用性"""
        self.available_tools = {}
        tools = ["nmap", "nikto", "gobuster", "nuclei", "sqlmap", "hydra", "ffuf"]
        
        for tool in tools:
            if shutil.which(tool):
                self.available_tools[tool] = True
            else:
                self.available_tools[tool] = False
    
    def check_command_security(self, command: str) -> SecurityCheckResult:
        """
        检查命令安全性
        
        Args:
            command: 要检查的命令
            
        Returns:
            SecurityCheckResult: 安全检查结果
        """
        warnings = []
        is_blocked = False
        risk_level = RiskLevel.LOW
        
        # 检查是否在禁止列表
        for blocked in self.BLOCKED_COMMANDS:
            if blocked.lower() in command.lower():
                return SecurityCheckResult(
                    is_safe=False,
                    risk_level=RiskLevel.CRITICAL,
                    warnings=[f"命令包含禁止的操作: {blocked}"],
                    blocked=True,
                    reason="命令被安全策略阻止"
                )
        
        # 检查高风险模式
        for pattern in self.HIGH_RISK_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                warnings.append(f"命令包含高风险操作模式")
                risk_level = RiskLevel.HIGH
                break
        
        # 根据工具类型评估风险
        if "sqlmap" in command and "--sql-shell" in command:
            warnings.append("SQLMap 交互式 shell 可能造成数据修改")
            risk_level = RiskLevel.HIGH
        
        if "hydra" in command:
            warnings.append("密码爆破可能触发账户锁定")
            risk_level = RiskLevel.HIGH
        
        if "nmap" in command:
            if any(x in command for x in ["--script", "-sC", "-sV"]):
                risk_level = RiskLevel.LOW
            else:
                risk_level = RiskLevel.LOW
        
        if "nikto" in command or "nuclei" in command:
            risk_level = RiskLevel.MEDIUM
        
        return SecurityCheckResult(
            is_safe=len(warnings) == 0,
            risk_level=risk_level,
            warnings=warnings,
            blocked=is_blocked
        )
    
    def execute(
        self,
        command: str,
        timeout: int = 300,
        show_progress: bool = True,
        progress_text: str = "执行中"
    ) -> ToolResult:
        """
        执行命令
        
        Args:
            command: 要执行的命令
            timeout: 超时时间（秒）
            show_progress: 是否显示进度
            progress_text: 进度文本
            
        Returns:
            ToolResult: 执行结果
        """
        start_time = time.time()
        
        try:
            if show_progress:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    console=self.console,
                    transient=True
                ) as progress:
                    task = progress.add_task(f"[cyan]{progress_text}...", total=None)
                    
                    process = subprocess.Popen(
                        command,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    output_lines = []
                    error_lines = []
                    
                    while process.poll() is None:
                        # 读取输出
                        if process.stdout:
                            line = process.stdout.readline()
                            if line:
                                output_lines.append(line)
                                progress.update(task, description=f"[cyan]{progress_text}... {line[:50]}")
                        
                        # 检查超时
                        if time.time() - start_time > timeout:
                            process.kill()
                            return ToolResult(
                                success=False,
                                output="".join(output_lines),
                                error=f"命令执行超时（{timeout}秒）",
                                execution_time=time.time() - start_time
                            )
                        
                        time.sleep(0.1)
                    
                    # 读取剩余输出
                    remaining_out, remaining_err = process.communicate()
                    output_lines.append(remaining_out)
                    error_lines.append(remaining_err)
            else:
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                try:
                    stdout, stderr = process.communicate(timeout=timeout)
                    output_lines = [stdout]
                    error_lines = [stderr]
                except subprocess.TimeoutExpired:
                    process.kill()
                    return ToolResult(
                        success=False,
                        error=f"命令执行超时（{timeout}秒）",
                        execution_time=time.time() - start_time
                    )
            
            execution_time = time.time() - start_time
            output = "".join(output_lines)
            error = "".join(error_lines)
            
            success = process.returncode == 0
            
            return ToolResult(
                success=success,
                output=output,
                error=error if error else None,
                execution_time=execution_time,
                findings=[]  # 由解析器填充
            )
            
        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                execution_time=time.time() - start_time
            )
    
    def is_tool_available(self, tool_name: str) -> bool:
        """检查工具是否可用"""
        return self.available_tools.get(tool_name, False)
    
    def get_available_tools(self) -> Dict[str, bool]:
        """获取所有工具可用性"""
        return self.available_tools.copy()
