"""
Nikto 工具封装
"""

import re
from typing import Dict, List, Any, Optional

from agent.tools.base import BaseTool, ToolInfo
from agent.core.models import RiskLevel, Finding


class NiktoTool(BaseTool):
    """Nikto Web 漏洞扫描工具"""
    
    @classmethod
    def get_info(cls) -> ToolInfo:
        return ToolInfo(
            name="nikto",
            description="Web 服务器漏洞扫描工具",
            risk_level=RiskLevel.MEDIUM,
            category="vulnerability_scanning",
            examples=[
                "nikto -h http://example.com",
                "nikto -h 192.168.1.1 -p 8080",
                "nikto -h https://example.com -ssl"
            ],
            options={
                "port": "-p (指定端口)",
                "ssl": "-ssl (强制 SSL)",
                "output": "-o (输出文件)",
                "format": "-Format (输出格式)"
            }
        )
    
    @classmethod
    def build_command(cls, target: str, options: Optional[Dict[str, Any]] = None) -> str:
        options = options or {}
        
        port = options.get("port", "")
        ssl = options.get("ssl", False)
        output_format = options.get("format", "txt")
        
        # 构建目标 URL
        if not target.startswith("http"):
            target = f"http://{target}"
        
        cmd_parts = ["nikto", "-h", target]
        
        if port:
            cmd_parts.extend(["-p", str(port)])
        
        if ssl:
            cmd_parts.append("-ssl")
        
        cmd_parts.extend(["-Format", output_format])
        
        return " ".join(cmd_parts)
    
    @classmethod
    def parse_output(cls, output: str) -> List[Finding]:
        findings = []
        
        # 解析 Nikto 输出
        # 示例: + OSVDB-3092: /admin/: This might be interesting...
        pattern = r"\+\s*(\S+):\s*(.+?):\s*(.+)"
        
        for match in re.finditer(pattern, output):
            vuln_id = match.group(1)
            path = match.group(2)
            description = match.group(3)
            
            findings.append(Finding(
                title=f"Nikto 发现: {path}",
                description=f"[{vuln_id}] {description}",
                severity=RiskLevel.MEDIUM,
                tool="nikto",
                raw_output=match.group(0),
                metadata={
                    "vulnerability_id": vuln_id,
                    "path": path
                }
            ))
        
        return findings
