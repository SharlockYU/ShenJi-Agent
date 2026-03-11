"""
扫描Agent - 负责端口扫描和服务检测
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


from agent.tools.nmap import NmapTool


from agent.tools.base import BaseTool, ToolInfo


class ScanAgent(WorkerAgent):
    """
    扫描Agent
    
    职责：
    1. 端口扫描
    2. 服务版本识别
    3. 服务指纹识别
    4. 操作系统检测
    """
    
    def __init__(self, agent_id: str = "1", config: Optional[Dict[str, Any]] = None):
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.SCAN,
            tools=["nmap"],
            config=config
        )
        self.console = Console()
        self.nmap_tool = NmapTool()
        self.executor = ToolExecutor(config.get("tools", {}) if config else {})
    
    def do_execute(self, task: AgentTask) -> ToolResult:
        """执行扫描任务"""
        if task.tool == "nmap":
            return self._execute_nmap_task(task)
        else:
            return super().do_execute(task)
    
    def _execute_nmap_task(self, task: AgentTask) -> ToolResult:
        """执行Nmap扫描任务"""
        start_time = time.time()
        
        try:
            # 获取Nmap配置
            nmap_config = self.config.get("tools", {}).get("nmap", {})
            
            # 构建参数
            arguments = []
            
            # 基本扫描参数
            arguments.extend(["-sV"])  # 版本检测
            
            
            # 根据配置添加参数
            scan_type = nmap_config.get("scan_type", "syn")
            if scan_type == "syn":
                arguments.append("-sS")  # SYN扫描
            elif scan_type == "udp":
                arguments.append("-sU")  # UDP扫描
            elif scan_type == "connect":
                arguments.append("-sT")  # TCP connect
            else:
                arguments.extend(["-sV"])  # 默认版本检测
            
            # 服务检测
            if nmap_config.get("service_detection", True):
                arguments.append("-sV")
            
            # 脚本扫描
            if nmap_config.get("script_scan"):
                scripts = nmap_config.get("scripts", "default")
                if scripts != "default":
                    arguments.extend([f"--script={scripts}"])
            
            # 操作系统检测
            if nmap_config.get("os_detection"):
                arguments.append("-O")
            
            # 构建目标
            target = str(task.target)
            
            # 构建命令
            command = f"nmap {' '.join(arguments)} {target}"
            
            self._log(f"执行Nmap扫描: {target}")
            self._log(f"命令: {command}")
            
            # 显示扫描进度
            self.console.print(f"\n[cyan]开始Nmap端口扫描...[/]")
            
            # 执行命令
            result = self.executor.execute(
                command,
                timeout=nmap_config.get("timeout", 300),
                show_progress=True,
                progress_text="Nmap扫描中"
            )
            
            execution_time = time.time() - start_time
            
            if result.success:
                self.console.print(f"[green]✓ Nmap扫描完成[/] ({execution_time:.2f}秒)")
                self._log(f"扫描完成，发现 {len(result.output.splitlines())} 行输出", "success")
            else:
                self.console.print(f"[red]✗ Nmap扫描失败[/]")
                self._log(f"扫描失败: {result.error}", "error")
            
            return result
            
        except Exception as e:
            error_msg = f"Nmap扫描异常: {str(e)}"
            self._log(error_msg, "error")
            return ToolResult(
                success=False,
                error=error_msg,
                execution_time=time.time() - start_time
            )
    
    def post_execute(self, task: AgentTask, result: ToolResult) -> ToolResult:
        """执行后处理"""
        if not result.success:
            return result
        
        if task.tool == "nmap":
            # 解析Nmap输出，提取关键信息
            parsed_info = self._parse_nmap_output(result.output)
            
            if parsed_info.get("open_ports"):
                self._log(f"发现开放端口: {len(parsed_info['open_ports'])} 个", "warning")
                # 报告发现
                for port_info in parsed_info["open_ports"]:
                    finding = {
                        "title": f"开放端口: {port_info.get('port', 'Unknown')}",
                        "description": port_info.get("service", "未知服务"),
                        "severity": "medium" if port_info.get("port", 0) < 1024 else "low",
                        "tool": "nmap",
                        "raw_output": port_info
                    }
                    self.send_message(
                        to_agent="master_main",
                        message_type="finding_report",
                        content={"finding": finding}
                    )
        
        # 更新结果
        result.parsed_data = parsed_info
        
        return result
    
    def _parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """解析Nmap输出"""
        parsed_info = {
            "open_ports": [],
            "services": [],
            "os": None
        }
        
        if not output:
            return parsed_info
        
        open_ports = []
        current_port = {}
        
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            
            # 检测端口行
            # 格式: 22/tcp   open  ssh
            # 或: 22/tcp   open  ssh  Debian (protocol 2.3.4)
            import re
            port_match = re.match(r'(\d+)/(tcp|udp)\s+open\s+(.+?)(?:\s+(.*))?', line)
            if port_match:
                port = port_match.group(1)
                service = port_match.group(2) if port_match.lastindex > 2 else "unknown"
                state = port_match.group(3) if len(port_match.groups()) > 3 else ""
                
                open_ports.append({
                    "port": port,
                    "protocol": "tcp" if "/tcp" in line else "udp",
                    "service": service.strip() if len(service) > 30 else service,
                    "state": state,
                    "version": port_match.group(4) if len(port_match.groups()) > 4 else ""
                })
            
            # 检测操作系统
            # 格式: OS: Linux
            # 或: Running: Linux 5.4.0
            os_match = re.search(r'OS:\s*(.+)', line)
            if os_match:
                parsed_info["os"] = os_match.group(1).strip()
            
            # 检测服务版本
            # 格式: 22/tcp   open  ssh  Ubuntu (protocol 2.3.4)
            version_match = re.search(r'vesion\s+(.+)', line)
            if version_match and parsed_info["open_ports"]:
                for port in parsed_info["open_ports"]:
                    if not port.get("version"):
                        port["version"] = version_match.group(1)
        
        return parsed_info
    
    def get_capabilities(self) -> Dict[str, Any]:
        """获取能力描述"""
        return {
            "agent_id": self.agent_id,
            "role": self.role.value,
            "status": self.status.value,
            "tools": self.tools,
            "capabilities": [
                "端口扫描",
                "服务版本识别",
                "操作系统检测"
                "脚本扫描"
            ],
            "description": "扫描Agent - 负责网络端口扫描和服务检测"
        }
    
    def display_scan_result(self, result: ToolResult) -> None:
        """显示扫描结果"""
        if not result.parsed_data:
            self.console.print(result.output)
            return
        
        ports = result.parsed_data.get("open_ports", [])
        
        if ports:
            table = Table(title="🔍 端口扫描结果")
            table.add_column("端口", style="cyan", width=10)
            table.add_column("协议", style="green", width=8)
            table.add_column("服务", style="white")
            table.add_column("状态", style="yellow", width=10)
            
            for port in ports:
                table.add_row(
                    str(port.get("port", "")),
                    port.get("protocol", ""),
                    port.get("service", "unknown")[:30],
                    port.get("state", "")
                )
            
            self.console.print(table)
        
        # 显示操作系统信息
        os = result.parsed_data.get("os")
        if os:
            self.console.print(Panel(
                f"检测到操作系统: {os}",
                title="💻 操作系统",
                border_style="blue"
            ))
