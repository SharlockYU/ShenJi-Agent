"""
Gobuster 工具封装
"""

import re
from typing import Dict, List, Any, Optional

from agent.tools.base import BaseTool, ToolInfo
from agent.core.models import RiskLevel, Finding


class GobusterTool(BaseTool):
    """Gobuster 目录枚举工具"""
    
    @classmethod
    def get_info(cls) -> ToolInfo:
        return ToolInfo(
            name="gobuster",
            description="目录和文件枚举工具",
            risk_level=RiskLevel.MEDIUM,
            category="enumeration",
            examples=[
                "gobuster dir -u http://example.com -w common.txt",
                "gobuster dns -d example.com -w subdomains.txt",
                "gobuster vhost -u http://example.com -w vhosts.txt"
            ],
            options={
                "mode": "dir/dns/vhost",
                "wordlist": "-w (字典文件路径)",
                "threads": "-t (线程数)",
                "extensions": "-x (文件扩展名)"
            }
        )
    
    @classmethod
    def build_command(cls, target: str, options: Optional[Dict[str, Any]] = None) -> str:
        options = options or {}
        
        mode = options.get("mode", "dir")
        wordlist = options.get("wordlist", "./data/wordlists/common.txt")
        threads = options.get("threads", 10)
        extensions = options.get("extensions", "")
        
        # 确保目标有协议
        if not target.startswith("http"):
            target = f"http://{target}"
        
        cmd_parts = ["gobuster", mode, "-u", target, "-w", wordlist, "-t", str(threads)]
        
        if extensions and mode == "dir":
            cmd_parts.extend(["-x", extensions])
        
        return " ".join(cmd_parts)
    
    @classmethod
    def parse_output(cls, output: str) -> List[Finding]:
        findings = []
        
        # 解析发现的目录
        dir_pattern = r"(/[^/]+)\s+\(Status:\s*(\d+)\s+\[Size:\s*(\d+)\]"
        for match in re.finditer(dir_pattern, output):
            path = match.group(1)
            status = match.group(2)
            size = match.group(3)
            
            findings.append(Finding(
                title=f"发现目录: {path}",
                description=f"发现可访问目录 {path} (状态: {status}, 大小: {size} bytes)",
                severity=RiskLevel.LOW,
                tool="gobuster",
                raw_output=match.group(0),
                metadata={
                    "path": path,
                    "status": status,
                    "size": int(size)
                }
            ))
        
        return findings
