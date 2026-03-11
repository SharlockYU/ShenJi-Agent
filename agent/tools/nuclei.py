"""
Nuclei 工具封装
"""

import re
from typing import Dict, List, Any, Optional

from agent.tools.base import BaseTool, ToolInfo
from agent.core.models import RiskLevel, Finding


class NucleiTool(BaseTool):
    """Nuclei 模板化漏洞扫描工具"""
    
    @classmethod
    def get_info(cls) -> ToolInfo:
        return ToolInfo(
            name="nuclei",
            description="基于模板的快速漏洞扫描工具",
            risk_level=RiskLevel.MEDIUM,
            category="vulnerability_scanning",
            examples=[
                "nuclei -u http://example.com",
                "nuclei -u http://example.com -severity critical",
                "nuclei -u http://example.com -tags cve"
            ],
            options={
                "templates": "-t (模板标签)",
                "severity": "-severity (low/medium/high/critical)",
                "rate_limit": "-rate-limit (请求速率限制)",
                "headless": "-headless (无头模式)"
            }
        )
    
    @classmethod
    def build_command(cls, target: str, options: Optional[Dict[str, Any]] = None) -> str:
        options = options or {}
        
        templates = options.get("templates", "default")
        severity = options.get("severity", "medium,high,critical")
        silent = options.get("silent", True)
        
        # 确保目标有协议
        if not target.startswith("http"):
            target = f"http://{target}"
        
        cmd_parts = ["nuclei", "-u", target]
        
        if templates != "default":
            cmd_parts.extend(["-t", templates])
        
        if severity:
            cmd_parts.extend(["-severity", severity])
        
        if silent:
            cmd_parts.append("-silent")
        
        return " ".join(cmd_parts)
    
    @classmethod
    def parse_output(cls, output: str) -> List[Finding]:
        findings = []
        
        # 解析 Nuclei 输出
        # 示例: [CVE-2021-1234] [high] http://example.com/vuln.php
        pattern = r"\[([A-Z]+-\d{4}-\d+)\]\s+\[(low|medium|high|critical|info)\]\s+(.+)"
        
        for match in re.finditer(pattern, output):
            template_id = match.group(1)
            severity_str = match.group(2).lower()
            url = match.group(3)
            
            severity_map = {
                "low": RiskLevel.LOW,
                "medium": RiskLevel.MEDIUM,
                "high": RiskLevel.HIGH,
                "critical": RiskLevel.CRITICAL,
                "info": RiskLevel.LOW
            }
            
            findings.append(Finding(
                title=f"Nuclei 发现: {template_id}",
                description=f"模板 {template_id} 在 {url} 触发",
                severity=severity_map.get(severity_str, RiskLevel.MEDIUM),
                tool="nuclei",
                raw_output=match.group(0),
                metadata={
                    "template_id": template_id,
                    "url": url,
                    "severity": severity_str
                }
            ))
        
        return findings
