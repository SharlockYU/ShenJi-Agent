"""
解析器模块 - 工具输出解析
"""

from typing import List, Optional
from agent.core.models import Finding, RiskLevel


class OutputParser:
    """输出解析器基类"""
    
    @staticmethod
    def parse_nmap_output(output: str) -> List[dict]:
        """解析 Nmap 输出"""
        results = []
        lines = output.split('\n')
        
        for line in lines:
            if 'tcp' in line.lower() and 'open' in line.lower():
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split('/')[0]
                    state = parts[1].strip()
                    service = parts[2].strip() if len(parts) > 2 else parts[2]
                    results.append({
                        "port": int(port),
                        "state": state,
                        "service": service
                    })
        
        return results
    
    @staticmethod
    def parse_nikto_output(output: str) -> List[dict]:
        """解析 Nikto 输出"""
        results = []
        lines = output.split('\n')
        
        for line in lines:
            if line.startswith('+') and 'OSVDB' in line:
                parts = line.split(':', 3)
                if len(parts) >= 4:
                    item_id = parts[0]
                    item = parts[1]
                    description = parts[2].strip()
                    results.append({
                        "id": item_id,
                        "item": item,
                        "description": description
                    })
        
        return results
