"""
规划节点 - 决定下一步执行什么工具
核心决策逻辑，使用LLM智能选择工具
"""

import json
import re
import logging
from typing import Dict, Any, List

from agent.core.state import PentestState, get_state_summary
from agent.llm.provider import LLMProvider

logger = logging.getLogger(__name__)


# 可用工具定义
AVAILABLE_TOOLS = {
    "http": {
        "name": "HTTP内容获取",
        "description": "获取网页内容，分析HTML结构、表单、链接、注释等",
        "category": "reconnaissance",
        "use_cases": [
            "首次访问目标",
            "分析网页结构",
            "查找隐藏信息和CTF线索",
            "检测flag"
        ]
    },
    "nmap": {
        "name": "Nmap端口扫描",
        "description": "扫描目标开放端口和服务版本",
        "category": "reconnaissance",
        "use_cases": [
            "发现开放端口",
            "识别服务版本",
            "检测潜在攻击面"
        ]
    },
    "gobuster": {
        "name": "Gobuster目录枚举",
        "description": "枚举Web目录和文件",
        "category": "enumeration",
        "use_cases": [
            "发现隐藏目录",
            "查找备份文件",
            "枚举API端点"
        ]
    },
    "nuclei": {
        "name": "Nuclei漏洞扫描",
        "description": "使用模板扫描已知漏洞",
        "category": "vulnerability",
        "use_cases": [
            "检测CVE漏洞",
            "扫描配置错误",
            "检测敏感信息泄露"
        ]
    },
    "nikto": {
        "name": "Nikto Web扫描",
        "description": "Web服务器安全扫描",
        "category": "vulnerability",
        "use_cases": [
            "检测Web服务器配置问题",
            "发现危险文件",
            "检测过时的服务器版本"
        ]
    }
}


def planner_node(state: PentestState) -> Dict[str, Any]:
    """
    规划节点 - 决定下一步执行什么工具

    逻辑:
    1. 检查是否已找到flag -> 结束
    2. 检查是否达到最大尝试次数 -> 结束
    3. 如果还没执行HTTP -> 执行HTTP
    4. 调用LLM分析当前状态并选择下一步工具
    5. 返回 next_action

    Args:
        state: 当前状态

    Returns:
        状态更新字典
    """
    logger.info("[Planner] 开始规划下一步动作...")

    # 1. 检查是否已找到flag
    if state.get("flag_found"):
        logger.info("[Planner] Flag已找到，任务完成")
        return {
            "is_complete": True,
            "complete_reason": "flag_found",
            "next_action": "end"
        }

    # 2. 检查是否达到最大尝试次数
    attempts = state.get("attempts", 0)
    max_attempts = state.get("max_attempts", 10)

    if attempts >= max_attempts:
        logger.info(f"[Planner] 达到最大尝试次数 {max_attempts}，任务结束")
        return {
            "is_complete": True,
            "complete_reason": "max_attempts_reached",
            "next_action": "end"
        }

    # 3. 如果还没执行HTTP，优先执行HTTP
    executed_tools = state.get("executed_tools", [])
    if "http" not in executed_tools:
        logger.info("[Planner] HTTP未执行，选择HTTP作为第一步")
        return {
            "next_action": "http",
            "current_tool": "http",
            "attempts": attempts + 1
        }

    # 4. 调用LLM决策下一步工具
    try:
        next_tool = llm_decide_next_tool(state)
        logger.info(f"[Planner] LLM选择工具: {next_tool}")

        return {
            "next_action": next_tool,
            "current_tool": next_tool,
            "attempts": attempts + 1
        }
    except Exception as e:
        logger.error(f"[Planner] LLM决策失败: {e}")
        # 使用规则引擎作为后备
        next_tool = rule_based_decision(state)
        logger.info(f"[Planner] 使用规则引擎选择: {next_tool}")

        return {
            "next_action": next_tool,
            "current_tool": next_tool,
            "attempts": attempts + 1
        }


def llm_decide_next_tool(state: PentestState) -> str:
    """
    使用LLM决策下一步工具

    Args:
        state: 当前状态

    Returns:
        下一步要执行的工具名称
    """
    # 初始化LLM
    config = state.get("config", {})
    llm_config = config.get("llm", {})

    llm_provider = LLMProvider(llm_config)
    llm_provider.initialize()

    # 构建上下文
    state_summary = get_state_summary(state)
    executed_tools = state.get("executed_tools", [])

    # 获取已执行工具的结果摘要
    results_summary = _build_results_summary(state)

    # 构建工具列表（排除已执行的）
    available_tools_list = []
    for tool_name, tool_info in AVAILABLE_TOOLS.items():
        if tool_name not in executed_tools:
            available_tools_list.append(
                f"- {tool_name}: {tool_info['description']} "
                f"(用途: {', '.join(tool_info['use_cases'][:2])})"
            )

    if not available_tools_list:
        return "end"

    prompt = f"""你是一个渗透测试专家，需要根据当前状态选择下一步要执行的工具。

=== 当前状态 ===
{state_summary}

=== 已执行工具的结果摘要 ===
{results_summary}

=== 可用工具列表 ===
{chr(10).join(available_tools_list)}

=== 已执行的工具 ===
{', '.join(executed_tools) or '无'}

请分析当前情况，选择最合适的下一步工具。

决策考虑因素：
1. 如果已经发现可疑端口(如22, 80, 443, 8080)，考虑进一步扫描
2. 如果发现隐藏目录线索，使用gobuster枚举
3. 如果发现Web应用，考虑漏洞扫描
4. 如果认为已经完成测试或没有更多有价值的信息，选择 "end"

请直接返回JSON格式的决策结果，不要包含其他文字：
{{
    "selected_tool": "工具名称或end",
    "reason": "选择原因",
    "confidence": 0.8
}}
"""

    response = llm_provider.generate(prompt)
    result = _parse_llm_response(response)

    next_tool = result.get("selected_tool", "end")

    # 验证工具是否有效
    if next_tool != "end" and next_tool not in AVAILABLE_TOOLS:
        logger.warning(f"[Planner] LLM返回无效工具: {next_tool}")
        return "end"

    # 验证工具是否已执行过
    if next_tool != "end" and next_tool in executed_tools:
        logger.warning(f"[Planner] 工具 {next_tool} 已执行过")
        return "end"

    return next_tool


def rule_based_decision(state: PentestState) -> str:
    """
    基于规则的决策（LLM不可用时的后备方案）

    Args:
        state: 当前状态

    Returns:
        下一步工具名称
    """
    executed_tools = state.get("executed_tools", [])

    # 按优先级选择工具
    tool_priority = ["nmap", "gobuster", "nuclei", "nikto"]

    for tool in tool_priority:
        if tool not in executed_tools:
            # 根据发现的信息调整优先级
            discovered_ports = state.get("discovered_ports", [])
            ctf_hints = state.get("ctf_hints", [])

            # 如果有CTF线索，优先枚举
            if ctf_hints and "gobuster" not in executed_tools:
                return "gobuster"

            # 如果发现非HTTP端口，优先nmap
            if discovered_ports and any(p not in [80, 443, 8080, 8443] for p in discovered_ports):
                if "nmap" not in executed_tools:
                    return "nmap"

            return tool

    return "end"


def _build_results_summary(state: PentestState) -> str:
    """构建已执行工具的结果摘要"""
    tools_results = state.get("tools_results", [])
    if not tools_results:
        return "暂无执行结果"

    summaries = []
    for result in tools_results[-3:]:  # 只取最近3个结果
        tool = result.get("tool", "unknown")
        summary = result.get("summary", "")

        if summary:
            summaries.append(f"[{tool}] {summary[:200]}")
        elif result.get("success"):
            summaries.append(f"[{tool}] 执行成功")
        else:
            summaries.append(f"[{tool}] 执行失败: {result.get('error', 'unknown')}")

    return "\n".join(summaries)


def _parse_llm_response(response: str) -> Dict[str, Any]:
    """解析LLM响应"""
    try:
        # 尝试提取JSON
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            return json.loads(json_match.group())
        return {"selected_tool": "end", "reason": "解析失败", "confidence": 0}
    except json.JSONDecodeError:
        # 尝试从文本中提取工具名
        for tool in AVAILABLE_TOOLS.keys():
            if tool in response.lower():
                return {"selected_tool": tool, "reason": "从文本提取", "confidence": 0.5}
        return {"selected_tool": "end", "reason": "无法解析", "confidence": 0}
