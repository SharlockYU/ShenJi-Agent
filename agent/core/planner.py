"""
计划生成器 - 根据目标信息生成渗透测试计划
支持LLM自主选择工具
"""

import json
import re
from typing import List, Optional, Dict, Any
from agent.core.models import (
    ExecutionPlan, Step, TargetInfo, RiskLevel, StepStatus
)
from agent.tools.http import HTTPTool
from agent.tools.base import BaseTool, ToolInfo
from agent.tools.nmap import NmapTool
from agent.tools.nikto import NiktoTool
from agent.tools.gobuster import GobusterTool
from agent.tools.nuclei import NucleiTool
from agent.llm.provider import LLMProvider


# 可用工具注册表
AVAILABLE_TOOLS = {
    "nmap": {
        "class": NmapTool,
        "name": "nmap",
        "description": "网络端口扫描和服务检测工具，用于发现开放端口、运行的服务和版本信息",
        "risk_level": "low",
        "category": "reconnaissance",
        "use_cases": [
            "需要了解目标开放了哪些端口",
            "需要识别目标运行的服务版本",
            "需要进行服务指纹识别",
            "需要发现潜在的攻击面"
        ],
        "command_template": "nmap -sV -sC {target}"
    },
    "gobuster": {
        "class": GobusterTool,
        "name": "gobuster",
        "description": "目录和文件枚举工具，用于发现隐藏的目录、文件和路径",
        "risk_level": "medium",
        "category": "enumeration",
        "use_cases": [
            "需要发现隐藏的Web目录",
            "需要枚举可能的备份文件",
            "需要查找管理员后台",
            "需要发现敏感文件路径"
        ],
        "command_template": "gobuster dir -u {url} -w ./data/wordlists/common.txt"
    },
    "nuclei": {
        "class": NucleiTool,
        "name": "nuclei",
        "description": "基于模板的快速漏洞扫描工具，使用社区维护的模板检测已知漏洞",
        "risk_level": "medium",
        "category": "vulnerability_scanning",
        "use_cases": [
            "需要检测已知CVE漏洞",
            "需要进行批量漏洞扫描",
            "需要识别Web应用漏洞",
            "需要检测配置错误"
        ],
        "command_template": "nuclei -u {url} -severity medium,high,critical"
    },
    "nikto": {
        "class": NiktoTool,
        "name": "nikto",
        "description": "Web服务器漏洞扫描工具，用于检测Web服务器配置问题和已知漏洞",
        "risk_level": "medium",
        "category": "vulnerability_scanning",
        "use_cases": [
            "需要检测Web服务器配置问题",
            "需要发现危险的CGI脚本",
            "需要检测过时的服务器版本",
            "需要识别Web服务器指纹"
        ],
        "command_template": "nikto -h {url}"
    },
    "http": {
        "class": HTTPTool,
        "name": "http",
        "description": "HTTP请求和网页内容分析工具，用于获取网页内容、分析页面结构",
        "risk_level": "low",
        "category": "reconnaissance",
        "use_cases": [
            "需要获取网页内容",
            "需要分析页面表单和链接",
            "需要检查HTTP响应头",
            "需要查找页面中的CTF线索"
        ],
        "command_template": "http_request {url}"
    }
}


class PlanGenerator:
    """
    执行计划生成器
    根据目标信息和上下文生成渗透测试计划
    支持LLM智能分析和自主工具选择
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._tool_config = self.config.get("tools", {})
        self.llm_provider: Optional[LLMProvider] = None
    
    def generate_plan(
        self,
        target: TargetInfo,
        strategy: str = "standard"
    ) -> ExecutionPlan:
        """
        生成执行计划
        
        Args:
            target: 目标信息
            strategy: 测试策略
            
        Returns:
            ExecutionPlan: 执行计划
        """
        # 第一步：使用HTTP工具获取网页内容
        steps = self._generate_initial_steps(target)
        
        plan = ExecutionPlan(
            target=target,
            strategy=strategy,
            steps=steps
        )
        
        return plan
    
    def _generate_initial_steps(self, target: TargetInfo) -> List[Step]:
        """生成初始步骤 - 首先获取和分析网页内容"""
        steps = []
        
        # 步骤1: HTTP内容获取和分析
        steps.append(Step(
            name="HTTP 内容获取和分析",
            tool="http",
            command=f"http_request {target}",
            description="使用HTTP工具获取网页内容，让LLM分析并自主选择后续工具",
            risk_level=RiskLevel.LOW,
            expected_output="网页内容、HTTP状态码、页面结构分析",
            status=StepStatus.PENDING
        ))
        
        return steps
    
    def get_available_tools_description(self) -> str:
        """获取可用工具的描述，用于LLM提示"""
        tools_desc = []
        for tool_name, tool_info in AVAILABLE_TOOLS.items():
            use_cases = "\n    - ".join(tool_info["use_cases"])
            tools_desc.append(f"""
### {tool_name}
- 描述: {tool_info['description']}
- 风险等级: {tool_info['risk_level']}
- 类别: {tool_info['category']}
- 适用场景:
    - {use_cases}
- 命令模板: {tool_info['command_template']}""")
        
        return "\n".join(tools_desc)
    
    def generate_next_steps_from_llm_choice(
        self,
        target: TargetInfo,
        http_result: Dict[str, Any],
        llm_tool_choice: Dict[str, Any]
    ) -> List[Step]:
        """
        根据LLM的工具选择结果生成后续步骤
        
        Args:
            target: 目标信息
            http_result: HTTP请求结果
            llm_tool_choice: LLM返回的工具选择结果
            
        Returns:
            新增的步骤列表
        """
        new_steps = []
        
        # 获取LLM选择的工具列表
        selected_tools = llm_tool_choice.get("selected_tools", [])
        
        for tool_info in selected_tools:
            tool_name = tool_info.get("name", "").lower()
            reason = tool_info.get("reason", "")
            priority = tool_info.get("priority", 5)
            
            if tool_name in AVAILABLE_TOOLS:
                step = self._create_step_from_tool(target, tool_name, reason, http_result, priority)
                if step:
                    new_steps.append(step)
        
        # 按优先级排序
        new_steps.sort(key=lambda s: s.metadata.get("priority", 5))
        
        return new_steps
    
    def _create_step_from_tool(
        self,
        target: TargetInfo,
        tool_name: str,
        reason: str,
        http_result: Dict[str, Any],
        priority: int = 5
    ) -> Optional[Step]:
        """根据工具名称创建执行步骤"""
        
        tool_info = AVAILABLE_TOOLS.get(tool_name)
        if not tool_info:
            return None
        
        # 构建目标URL
        if target.scheme:
            url = f"{target.scheme}://{target.host}"
        else:
            url = f"http://{target.host}"
        
        # 构建命令
        command = tool_info["command_template"].format(
            target=target.host,
            url=url
        )
        
        # 风险等级映射
        risk_map = {
            "low": RiskLevel.LOW,
            "medium": RiskLevel.MEDIUM,
            "high": RiskLevel.HIGH,
            "critical": RiskLevel.CRITICAL
        }
        risk_level = risk_map.get(tool_info["risk_level"], RiskLevel.LOW)
        
        # 创建步骤名称
        name_map = {
            "nmap": "Nmap 端口扫描",
            "gobuster": "Gobuster 目录枚举",
            "nuclei": "Nuclei 漏洞扫描",
            "nikto": "Nikto Web漏洞扫描",
            "http": "HTTP 内容分析"
        }
        
        return Step(
            name=name_map.get(tool_name, f"{tool_name} 扫描"),
            tool=tool_name,
            command=command,
            description=f"LLM选择原因: {reason}" if reason else tool_info["description"],
            risk_level=risk_level,
            expected_output=tool_info["description"],
            status=StepStatus.PENDING,
            metadata={"http_result": http_result, "tool_category": tool_info["category"], "priority": priority}
        )
    
    def generate_next_steps_from_analysis(
        self,
        target: TargetInfo,
        http_result: Dict[str, Any],
        llm_analysis: str
    ) -> List[Step]:
        """
        根据LLM分析结果生成后续步骤（向后兼容方法）
        
        Args:
            target: 目标信息
            http_result: HTTP请求结果
            llm_analysis: LLM分析结果
            
        Returns:
            新增的步骤列表
        """
        new_steps = []
        analysis_lower = llm_analysis.lower()
        
        # 如果分析建议进行端口扫描
        if "port" in analysis_lower or "nmap" in analysis_lower or "scan" in analysis_lower:
            new_steps.append(self._create_nmap_step(target))
        
        # 如果分析建议进行目录枚举
        if "directory" in analysis_lower or "gobuster" in analysis_lower or "dir" in analysis_lower:
            new_steps.append(self._create_gobuster_step(target))
        
        # 如果分析建议进行漏洞扫描
        if "vulnerability" in analysis_lower or "nikto" in analysis_lower or "nuclei" in analysis_lower:
            new_steps.append(self._create_nuclei_step(target))
        
        # 如果发现CTF相关线索
        if "ctf" in analysis_lower or "flag" in analysis_lower:
            new_steps.append(self._create_ctf_step(target, http_result))
        
        return new_steps
    
    def _create_nmap_step(self, target: TargetInfo) -> Step:
        """创建Nmap端口扫描步骤"""
        return Step(
            name="Nmap 端口扫描",
            tool="nmap",
            command=f"nmap -sV -sC {target.host}",
            description="扫描目标开放端口和运行服务版本",
            risk_level=RiskLevel.LOW,
            expected_output="开放端口列表和服务版本信息",
            status=StepStatus.PENDING
        )
    
    def _create_gobuster_step(self, target: TargetInfo) -> Step:
        """创建Gobuster目录枚举步骤"""
        wordlist = self._tool_config.get("gobuster", {}).get(
            "wordlist", "./data/wordlists/common.txt"
        )
        
        if target.scheme:
            url = f"{target.scheme}://{target.host}"
        else:
            url = f"http://{target.host}"
        
        return Step(
            name="Gobuster 目录枚举",
            tool="gobuster",
            command=f"gobuster dir -u {url} -w {wordlist}",
            description="枚举Web目录和隐藏文件",
            risk_level=RiskLevel.MEDIUM,
            expected_output="发现的目录和文件路径",
            status=StepStatus.PENDING
        )
    
    def _create_nuclei_step(self, target: TargetInfo) -> Step:
        """创建Nuclei漏洞扫描步骤"""
        if target.scheme:
            url = f"{target.scheme}://{target.host}"
        else:
            url = f"http://{target.host}"
        
        return Step(
            name="Nuclei 漏洞扫描",
            tool="nuclei",
            command=f"nuclei -u {url} -severity medium,high,critical",
            description="使用模板扫描已知漏洞",
            risk_level=RiskLevel.MEDIUM,
            expected_output="已识别的漏洞和安全问题",
            status=StepStatus.PENDING
        )
    
    def _create_ctf_step(self, target: TargetInfo, http_result: Dict[str, Any]) -> Step:
        """创建CTF分析步骤"""
        return Step(
            name="CTF 线索分析",
            tool="http",
            command=f"ctf_analyze {target}",
            description="深度分析CTF线索，检查HTML注释、隐藏字段、源码等",
            risk_level=RiskLevel.LOW,
            expected_output="CTF相关线索和可能的flag位置",
            status=StepStatus.PENDING,
            metadata={"http_result": http_result}
        )
