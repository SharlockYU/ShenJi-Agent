"""
Nmap 工具封装
"""

import re
from typing import Dict, List, Any, Optional

from agent.tools.base import BaseTool, ToolInfo
from agent.core.models import RiskLevel, Finding


class NmapTool(BaseTool):
    """Nmap 端口扫描工具"""
    
    @classmethod
    def get_info(cls) -> ToolInfo:
        return ToolInfo(
            name="nmap",
            description="网络端口扫描和服务检测工具",
            risk_level=RiskLevel.LOW,
            category="reconnaissance",
            examples=[
                "nmap -sV -sC 192.168.1.1",
                "nmap -p- 1000 192.168.1.1",
                "nmap --script vuln 192.168.1.1"
            ],
            options={
                "scan_type": "-sS (TCP SYN), -sT (TCP Connect), -sU (UDP), -sV (Version)",
                "port_spec": "-p 22,80,443 or -p-1000",
                "scripts": "--script default, vuln, auth"
            }
        )
    
    @classmethod
    def build_command(cls, target: str, options: Optional[Dict[str, Any]] = None) -> str:
        options = options or {}
        
        scan_type = options.get("scan_type", "-sV -sC")
        ports = options.get("ports", "")
        scripts = options.get("scripts", "")
        
        cmd_parts = ["nmap", scan_type]
        
        if ports:
            cmd_parts.append(f"-p {ports}")
        
        if scripts:
            cmd_parts.append(f"--script {scripts}")
        
        cmd_parts.append(target)
        
        return " ".join(cmd_parts)
    
    @classmethod
    def parse_output(cls, output: str) -> List[Finding]:
        findings = []
        
        # 解析开放端口
        port_pattern = r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(.+)?"
        for match in re.finditer(port_pattern, output):
            port = match.group(1)
            protocol = match.group(2)
            status = match.group(3)
            service = match.group(4) or "unknown"
            
            if status == "open":
                findings.append(Finding(
                    title=f"开放端口: {port}/{protocol}",
                    description=f"发现开放端口 {port}/{protocol} 运行服务: {service.strip()}",
                    severity=RiskLevel.LOW,
                    tool="nmap",
                    raw_output=match.group(0),
                    metadata={
                        "port": int(port),
                        "protocol": protocol,
                        "service": service.strip()
                    }
                ))
        
        return findings
