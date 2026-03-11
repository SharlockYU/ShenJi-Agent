"""
漏洞Agent - 负责漏洞扫描
"""

import time
from typing import Optional, Dict, Any
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from agent.agents.base import AgentRole, AgentStatus, AgentTask
from agent.agents.worker import WorkerAgent
from agent.core.models import ToolResult
from agent.core.executor import ToolExecutor
from agent.tools.nuclei import NucleiTool
from agent.tools.nikto import NiktoTool
from agent.tools.base import BaseTool, ToolInfo
import re


class VulnAgent(WorkerAgent):
    """
    漏洞Agent
    
    职责：
    1. 漏洞扫描
    2. 已知CVE检测
    3. 安全配置检查
    4. Web应用漏洞发现
    """
    
    def __init__(self, agent_id: str = "1", config: Optional[Dict[str, Any]] = None):
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.VULN,
            tools=["nuclei", "nikto"],
            config=config
        )
        self.console = Console()
        self.nuclei_tool = NucleiTool()
        self.nikto_tool = NiktoTool()
        self.executor = ToolExecutor(config.get("tools", {}) if config else {})
    
    def do_execute(self, task: AgentTask) -> ToolResult:
        """执行漏洞扫描任务"""
        if task.tool == "nuclei":
            return self._execute_nuclei_task(task)
        elif task.tool == "nikto":
            return self._execute_nikto_task(task)
        else:
            return super().do_execute(task)
    
    def _execute_nuclei_task(self, task: AgentTask) -> ToolResult:
        """执行Nuclei漏洞扫描任务"""
        start_time = time.time()
        
        try:
            # 获取Nuclei配置
            nuclei_config = self.config.get("tools", {}).get("nuclei", {})
            
            # 构建目标URL
            if task.target.scheme:
                url = f"{task.target.scheme}://{task.target.host}"
            else:
                url = f"http://{task.target.host}"
            
            # 构建命令
            severity = nuclei_config.get("severity", "medium,high,critical")
            command = f"nuclei -u {url} -severity {severity}"
            
            self._log(f"执行Nuclei漏洞扫描: {url}")
            self._log(f"命令: {command}")
            
            # 显示进度
            self.console.print(f"\n[cyan]开始Nuclei漏洞扫描...[/]")
            
            # 执行命令
            result = self.executor.execute(
                command,
                timeout=nuclei_config.get("timeout", 300),
                show_progress=True,
                progress_text="Nuclei扫描中"
            )
            
            execution_time = time.time() - start_time
            
            if result.success:
                self.console.print(f"[green]✓ Nuclei扫描完成[/] ({execution_time:.2f}秒)")
                self._log(f"扫描完成", "success")
                self._parse_and_report_vulnerabilities(result.output)
            else:
                self.console.print(f"[red]✗ Nuclei扫描失败[/]")
                self._log(f"扫描失败: {result.error}", "error")
            
            return result
            
        except Exception as e:
            error_msg = f"Nuclei扫描异常: {str(e)}"
            self._log(error_msg, "error")
            return ToolResult(
                success=False,
                error=error_msg,
                execution_time=time.time() - start_time
            )
    
    def _execute_nikto_task(self, task: AgentTask) -> ToolResult:
        """执行Nikto漏洞扫描任务"""
        start_time = time.time()
        
        try:
            # 获取Nikto配置
            nikto_config = self.config.get("tools", {}).get("nikto", {})
            
            # 构建目标URL
            if task.target.scheme:
                url = f"{task.target.scheme}://{task.target.host}"
            else:
                url = f"http://{task.target.host}"
            
            # 构建命令
            command = f"nikto -h {url}"
            
            self._log(f"执行Nikto漏洞扫描: {url}")
            self._log(f"命令: {command}")
            
            # 显示进度
            self.console.print(f"\n[cyan]开始Nikto Web漏洞扫描...[/]")
            
            # 执行命令
            result = self.executor.execute(
                command,
                timeout=nikto_config.get("timeout", 300),
                show_progress=True,
                progress_text="Nikto扫描中"
            )
            
            execution_time = time.time() - start_time
            
            if result.success:
                self.console.print(f"[green]✓ Nikto扫描完成[/] ({execution_time:.2f}秒)")
                self._log(f"扫描完成", "success")
                self._parse_and_report_vulnerabilities(result.output)
            else:
                self.console.print(f"[red]✗ Nikto扫描失败[/]")
                self._log(f"扫描失败: {result.error}", "error")
            
            return result
            
        except Exception as e:
            error_msg = f"Nikto扫描异常: {str(e)}"
            self._log(error_msg, "error")
            return ToolResult(
                success=False,
                error=error_msg,
                execution_time=time.time() - start_time
            )
    
    def _parse_and_report_vulnerabilities(self, output: str) -> None:
        """解析漏洞扫描结果并报告"""
        vulnerabilities = []
        
        # 解析Nuclei输出
        nuclei_pattern = re.findall(r'\[(\w+)\]\s+(.+?)\[(\w+)\]', output)
        for match in nuclei_pattern:
            severity = match[0]
            name = match[1]
            vulnerabilities.append({
                "name": name,
                "severity": severity,
                "type": "nuclei"
            })
            # 报告发现
            self.send_message(
                to_agent="master_main",
                message_type="finding_report",
                content={
                    "finding": {
                        "title": f"漏洞: {name}",
                        "severity": severity,
                        "tool": "nuclei",
                        "raw_output": match[0]
                    }
                }
            )
        
        # 解析Nikto输出
        nikto_patterns = [
            (r'\+ (\w+/\d+):\s*(.+)', re.IGNORECASE | re.MULTILINE),
            (r'OSVDB-\d+:\s*(.+)', re.IGNORECASE | re.MULTILINE),
            (r'Server:\s*(.+)', re.IGNORECASE | re.MULTILINE),
        ]
        
        for pattern, flags in nikto_patterns:
            if re.search(pattern, output, flags):
                matches = re.findall(pattern, output, flags)
                for match in matches:
                    vulnerabilities.append({
                        "type": "nikto",
                        "detail": match.strip() if isinstance(match, str) else match
                    })
        
        return vulnerabilities
    
    def post_execute(self, task: AgentTask, result: ToolResult) -> ToolResult:
        """执行后处理"""
        if not result.success:
            return result
        
        # 解析漏洞信息
        vulnerabilities = self._parse_and_report_vulnerabilities(result.output)
        
        if vulnerabilities:
            self._log(f"发现 {len(vulnerabilities)} 个潜在漏洞", "warning")
        
        return result
    
    def get_capabilities(self) -> Dict[str, Any]:
        """获取能力描述"""
        return {
            "agent_id": self.agent_id,
            "role": self.role.value,
            "status": self.status.value,
            "tools": self.tools,
            "capabilities": [
                "CVE漏洞扫描",
                "Web应用漏洞检测",
                "配置安全检查",
                "服务器指纹识别"
            ],
            "description": "漏洞Agent - 负责漏洞扫描和安全检测"
        }
