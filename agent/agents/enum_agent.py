"""
枚举Agent - 负责目录和文件枚举
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
from agent.tools.gobuster import GobusterTool
from agent.tools.base import BaseTool, ToolInfo


class EnumAgent(WorkerAgent):
    """
    枚举Agent
    
    职责：
    1. 目录枚举
    2. 文件枚举
    3. 隐藏路径发现
    4. 备份文件发现
    """
    
    def __init__(self, agent_id: str = "1", config: Optional[Dict[str, Any]] = None):
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.ENUM,
            tools=["gobuster"],
            config=config
        )
        self.console = Console()
        self.gobuster_tool = GobusterTool()
        self.executor = ToolExecutor(config.get("tools", {}) if config else {})
    
    def do_execute(self, task: AgentTask) -> ToolResult:
        """执行枚举任务"""
        if task.tool == "gobuster":
            return self._execute_gobuster_task(task)
        else:
            return super().do_execute(task)
    
    def _execute_gobuster_task(self, task: AgentTask) -> ToolResult:
        """执行Gobuster目录枚举任务"""
        start_time = time.time()
        
        try:
            # 获取Gobuster配置
            gobuster_config = self.config.get("tools", {}).get("gobuster", {})
            
            # 构建目标URL
            if task.target.scheme:
                url = f"{task.target.scheme}://{task.target.host}"
            else:
                url = f"http://{task.target.host}"
            
            # 获取字典列表路径
            wordlist = gobuster_config.get("wordlist", "./data/wordlists/common.txt")
            
            # 构建命令
            threads = gobuster_config.get("threads", "10")
            command = f"gobuster dir -u {url} -w {wordlist} -t {threads}"
            
            self._log(f"执行Gobuster目录枚举: {url}")
            self._log(f"命令: {command}")
            
            # 显示进度
            self.console.print(f"\n[cyan]开始Gobuster目录枚举...[/]")
            
            # 执行命令
            result = self.executor.execute(
                command,
                timeout=gobuster_config.get("timeout", 300),
                show_progress=True,
                progress_text="Gobuster枚举中"
            )
            
            execution_time = time.time() - start_time
            
            if result.success:
                self.console.print(f"[green]✓ Gobuster枚举完成[/] ({execution_time:.2f}秒)")
                self._log(f"枚举完成", "success")
                # 解析发现的目录
                directories = self._parse_gobuster_output(result.output)
                
                if directories:
                    self._log(f"发现 {len(directories)} 个目录", "warning")
                    # 报告发现
                    for directory in directories:
                        finding = {
                            "title": f"发现目录: {directory}",
                            "description": "通过Gobuster发现的目录",
                            "severity": "low",
                            "tool": "gobuster",
                            "raw_output": directory
                        }
                        self.send_message(
                            to_agent="master_main",
                            message_type="finding_report",
                            content={"finding": finding}
                        )
            else:
                self.console.print(f"[red]✗ Gobuster枚举失败[/]")
                self._log(f"枚举失败: {result.error}", "error")
            
            return result
            
        except Exception as e:
            error_msg = f"Gobuster枚举异常: {str(e)}"
            self._log(error_msg, "error")
            return ToolResult(
                success=False,
                error=error_msg,
                execution_time=time.time() - start_time
            )
    
    def _parse_gobuster_output(self, output: str) -> list:
        """解析Gobuster输出"""
        import re
        directories = []
        
        # 匹配目录行
        dir_patterns = [
            r'^\s*(\d+)\s+(.*?)\s+([^\s]+)\s*$',
            r'^\s*(\d+)/(.*)\s+([^\s]+)\s*$',
        ]
        
        for line in output.splitlines():
            for pattern in dir_patterns:
                match = re.search(pattern, line)
                if match:
                    dir_path = match.group(1)
                    if dir_path not in directories:
                        directories.append(dir_path)
        
        return directories
    
    def post_execute(self, task: AgentTask, result: ToolResult) -> ToolResult:
        """执行后处理"""
        if not result.success:
            return result
        
        # 解析发现的目录
        directories = self._parse_gobuster_output(result.output)
        
        if directories:
            self._log(f"发现 {len(directories)} 个目录", "warning")
            # 报告发现
            for directory in directories:
                finding = {
                    "title": f"发现目录: {directory}",
                    "description": "通过Gobuster发现的目录",
                    "severity": "low",
                    "tool": "gobuster",
                    "raw_output": directory
                }
                self.send_message(
                    to_agent="master_main",
                    message_type="finding_report",
                    content={"finding": finding}
                )
        
        return result
    
    def get_capabilities(self) -> Dict[str, Any]:
        """获取能力描述"""
        return {
            "agent_id": self.agent_id,
            "role": self.role.value,
            "status": self.status.value,
            "tools": self.tools,
            "capabilities": [
                "目录枚举",
                "文件枚举",
                "隐藏路径发现",
                "备份文件发现"
            ],
            "description": "枚举Agent - 负责目录和文件枚举"
        }
