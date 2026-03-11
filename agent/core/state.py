"""
LangGraph 状态定义
定义渗透测试Agent的核心状态结构
"""

import operator
from typing import TypedDict, List, Dict, Any, Optional, Annotated


def merge_lists(left: List, right: List) -> List:
    """合并两个列表，去重"""
    if not left:
        return right
    if not right:
        return left
    # 对于字典列表，基于特定字段去重
    if isinstance(right[0], dict):
        seen = set()
        result = []
        for item in left + right:
            # 使用工具名+时间戳或id作为唯一标识
            key = item.get('id') or item.get('tool') or str(item)
            if key not in seen:
                seen.add(key)
                result.append(item)
        return result
    # 对于普通列表，直接去重
    return list(set(left + right))


def merge_string_lists(left: List[str], right: List[str]) -> List[str]:
    """合并字符串列表，去重"""
    if not left:
        return right
    if not right:
        return left
    return list(set(left + right))


def merge_dict(left: Dict, right: Dict) -> Dict:
    """合并字典"""
    if not left:
        return right
    if not right:
        return left
    return {**left, **right}


class PentestState(TypedDict):
    """
    渗透测试状态定义

    使用 Annotated 类型实现状态合并策略
    """

    # ============ 目标信息 ============
    target: str  # 目标地址 (URL, IP, 或 domain:port)
    target_info: Dict[str, Any]  # 解析后的目标信息

    # ============ 执行状态 ============
    executed_tools: List[str]  # 已执行的工具列表
    current_tool: str  # 当前要执行的工具
    next_action: str  # 下一步动作 (http/nmap/gobuster/nuclei/nikto/end)

    # ============ 结果累积 (自动合并) ============
    tools_results: Annotated[List[Dict], merge_lists]  # 所有工具执行结果
    findings: Annotated[List[Dict], merge_lists]  # 发现的问题
    messages: Annotated[List[str], merge_string_lists]  # 日志消息

    # ============ 目标知识 (累积发现) ============
    discovered_ports: Annotated[List[int], merge_string_lists]  # 发现的开放端口
    discovered_paths: Annotated[List[str], merge_string_lists]  # 发现的目录/路径
    discovered_vulns: Annotated[List[Dict], merge_lists]  # 发现的漏洞
    ctf_hints: Annotated[List[str], merge_string_lists]  # CTF线索

    # ============ 控制状态 ============
    attempts: int  # 当前尝试次数
    max_attempts: int  # 最大尝试次数
    flag_found: bool  # 是否找到flag
    flag_value: str  # flag值
    is_complete: bool  # 是否完成
    complete_reason: str  # 完成原因

    # ============ LLM决策 ============
    llm_analysis: str  # LLM分析结果
    confidence: float  # 决策置信度 (0-1)

    # ============ 配置 ============
    config: Dict[str, Any]  # 配置信息


def create_initial_state(target: str, config: Dict[str, Any] = None) -> PentestState:
    """
    创建初始状态

    Args:
        target: 目标地址
        config: 配置字典

    Returns:
        初始化的状态字典
    """
    from agent.core.models import TargetInfo

    # 解析目标信息
    target_info_obj = TargetInfo.parse(target)

    return PentestState(
        # 目标信息
        target=target,
        target_info={
            "host": target_info_obj.host,
            "port": target_info_obj.port,
            "scheme": target_info_obj.scheme,
            "target_type": target_info_obj.target_type,
            "original": str(target_info_obj)
        },

        # 执行状态
        executed_tools=[],
        current_tool="",
        next_action="http",  # 默认从HTTP开始

        # 结果累积
        tools_results=[],
        findings=[],
        messages=[],

        # 目标知识
        discovered_ports=[],
        discovered_paths=[],
        discovered_vulns=[],
        ctf_hints=[],

        # 控制状态
        attempts=0,
        max_attempts=config.get("max_attempts", 10) if config else 10,
        flag_found=False,
        flag_value="",
        is_complete=False,
        complete_reason="",

        # LLM决策
        llm_analysis="",
        confidence=0.0,

        # 配置
        config=config or {}
    )


def state_to_dict(state: PentestState) -> Dict[str, Any]:
    """
    将状态转换为可序列化的字典

    Args:
        state: 状态对象

    Returns:
        可序列化的字典
    """
    return {
        "target": state.get("target", ""),
        "target_info": state.get("target_info", {}),
        "executed_tools": state.get("executed_tools", []),
        "current_tool": state.get("current_tool", ""),
        "next_action": state.get("next_action", ""),
        "tools_results": state.get("tools_results", []),
        "findings": state.get("findings", []),
        "messages": state.get("messages", []),
        "discovered_ports": list(state.get("discovered_ports", [])),
        "discovered_paths": list(state.get("discovered_paths", [])),
        "discovered_vulns": state.get("discovered_vulns", []),
        "ctf_hints": list(state.get("ctf_hints", [])),
        "attempts": state.get("attempts", 0),
        "max_attempts": state.get("max_attempts", 10),
        "flag_found": state.get("flag_found", False),
        "flag_value": state.get("flag_value", ""),
        "is_complete": state.get("is_complete", False),
        "complete_reason": state.get("complete_reason", ""),
        "llm_analysis": state.get("llm_analysis", ""),
        "confidence": state.get("confidence", 0.0),
    }


def get_state_summary(state: PentestState) -> str:
    """
    获取状态摘要，用于LLM上下文

    Args:
        state: 当前状态

    Returns:
        状态摘要字符串
    """
    lines = [
        f"目标: {state.get('target', 'unknown')}",
        f"已执行工具: {', '.join(state.get('executed_tools', [])) or '无'}",
        f"当前尝试: {state.get('attempts', 0)}/{state.get('max_attempts', 10)}",
        f"发现端口: {', '.join(map(str, state.get('discovered_ports', []))) or '无'}",
        f"发现路径: {', '.join(state.get('discovered_paths', [])[:10]) or '无'}",
        f"CTF线索: {', '.join(state.get('ctf_hints', [])[:5]) or '无'}",
        f"Flag状态: {'已找到' if state.get('flag_found') else '未找到'}",
    ]
    return "\n".join(lines)
