"""
分析节点 - 处理工具执行结果
提取有价值信息，检测flag，更新目标知识库
"""

import re
import logging
from typing import Dict, Any, List

from agent.core.state import PentestState

logger = logging.getLogger(__name__)


# 常见flag格式
FLAG_PATTERNS = [
    r'flag\{[^}]+\}',
    r'FLAG\{[^}]+\}',
    r'ctf\{[^}]+\}',
    r'CTF\{[^}]+\}',
    r'key\{[^}]+\}',
    r'KEY\{[^}]+\}',
    r'hctf\{[^}]+\}',
    r'sctf\{[^}]+\}',
    r'actf\{[^}]+\}',
]


def analyzer_node(state: PentestState) -> Dict[str, Any]:
    """
    分析节点 - 处理工具执行结果

    功能:
    1. 检查结果中是否有flag
    2. 提取有价值的信息(端口、路径、漏洞等)
    3. 更新目标知识库
    4. 生成分析摘要

    Args:
        state: 当前状态

    Returns:
        状态更新字典
    """
    logger.info("[Analyzer] 开始分析执行结果...")

    # 获取最近的执行结果
    tools_results = state.get("tools_results", [])
    if not tools_results:
        return {}

    latest_result = tools_results[-1]
    tool_name = latest_result.get("tool", "unknown")

    logger.info(f"[Analyzer] 分析 {tool_name} 的结果")

    updates = {}

    # 1. 检查flag
    flag_found, flag_value = _check_flag_in_result(latest_result, state)
    if flag_found:
        logger.info(f"[Analyzer] 发现FLAG: {flag_value}")
        updates["flag_found"] = True
        updates["flag_value"] = flag_value
        updates["is_complete"] = True
        updates["complete_reason"] = "flag_found"
        updates["messages"] = [f"[Analyzer] 🚩 FLAG 已找到: {flag_value}"]
        return updates

    # 2. 如果是HTTP结果，深度分析内容
    if tool_name == "http" and latest_result.get("success"):
        http_updates = _analyze_http_result(latest_result, state)
        updates.update(http_updates)

    # 3. 如果是Nmap结果，分析端口
    if tool_name == "nmap" and latest_result.get("success"):
        nmap_updates = _analyze_nmap_result(latest_result, state)
        updates.update(nmap_updates)

    # 4. 如果是Gobuster结果，分析路径
    if tool_name == "gobuster" and latest_result.get("success"):
        gobuster_updates = _analyze_gobuster_result(latest_result, state)
        updates.update(gobuster_updates)

    # 5. 生成分析摘要
    analysis_summary = _generate_analysis_summary(latest_result, state, updates)
    updates["llm_analysis"] = analysis_summary
    updates["messages"] = [f"[Analyzer] 分析完成: {analysis_summary[:100]}"]

    logger.info(f"[Analyzer] 分析完成: {analysis_summary[:100]}")

    return updates


def _check_flag_in_result(result: Dict[str, Any], state: PentestState) -> tuple:
    """
    检查结果中是否包含flag

    Args:
        result: 工具执行结果
        state: 当前状态

    Returns:
        (是否找到flag, flag值)
    """
    # 检查已知flag
    if state.get("flag_found"):
        return True, state.get("flag_value", "")

    # 收集所有可能包含flag的文本
    texts_to_check = []

    # 从结果中提取文本
    if result.get("output"):
        texts_to_check.append(str(result["output"]))
    if result.get("details"):
        details = result["details"]
        if isinstance(details, dict):
            for value in details.values():
                if isinstance(value, str):
                    texts_to_check.append(value)
                elif isinstance(value, list):
                    texts_to_check.extend(str(v) for v in value)

    # 从状态中获取CTF提示
    ctf_hints = state.get("ctf_hints", [])
    texts_to_check.extend(ctf_hints)

    # 从发现中获取
    findings = state.get("findings", [])
    for finding in findings:
        if isinstance(finding, dict):
            texts_to_check.append(str(finding.get("title", "")))
            texts_to_check.append(str(finding.get("description", "")))
            if finding.get("details"):
                texts_to_check.append(str(finding["details"]))

    # 搜索flag
    all_text = " ".join(texts_to_check)
    for pattern in FLAG_PATTERNS:
        matches = re.findall(pattern, all_text, re.IGNORECASE)
        if matches:
            return True, matches[0]

    return False, ""


def _analyze_http_result(result: Dict[str, Any], state: PentestState) -> Dict[str, Any]:
    """分析HTTP结果"""
    updates = {}
    details = result.get("details", {})

    # 提取更多CTF线索
    ctf_keywords = ['hidden', 'secret', 'password', 'admin', 'flag', 'ctf',
                   'decode', 'base64', 'token', 'api_key', 'credential']

    new_hints = []
    for keyword in ctf_keywords:
        # 检查是否已存在
        existing_hints = state.get("ctf_hints", [])
        if keyword not in existing_hints:
            # 在结果中搜索
            result_str = str(result).lower()
            if keyword in result_str:
                new_hints.append(keyword)

    if new_hints:
        updates["ctf_hints"] = new_hints

    # 检查发现的路径
    paths = details.get("paths", [])
    if paths:
        # 过滤出新的路径
        existing_paths = state.get("discovered_paths", [])
        new_paths = [p for p in paths if p not in existing_paths]
        if new_paths:
            updates["discovered_paths"] = new_paths

    return updates


def _analyze_nmap_result(result: Dict[str, Any], state: PentestState) -> Dict[str, Any]:
    """分析Nmap结果"""
    updates = {}
    details = result.get("details", {})

    # 提取端口信息
    ports = details.get("open_ports", [])
    if ports:
        existing_ports = state.get("discovered_ports", [])
        new_ports = [p for p in ports if p not in existing_ports]
        if new_ports:
            updates["discovered_ports"] = new_ports
            logger.info(f"[Analyzer] 发现新端口: {new_ports}")

            # 检查敏感端口
            sensitive_ports = {
                21: "FTP",
                22: "SSH",
                23: "Telnet",
                25: "SMTP",
                3306: "MySQL",
                5432: "PostgreSQL",
                6379: "Redis",
                27017: "MongoDB",
                9200: "Elasticsearch"
            }

            for port in new_ports:
                if port in sensitive_ports:
                    updates.setdefault("findings", []).append({
                        "tool": "nmap",
                        "type": "sensitive_port",
                        "title": f"敏感端口: {port} ({sensitive_ports[port]})",
                        "description": f"发现敏感服务端口 {port} ({sensitive_ports[port]})，可能存在安全风险"
                    })

    return updates


def _analyze_gobuster_result(result: Dict[str, Any], state: PentestState) -> Dict[str, Any]:
    """分析Gobuster结果"""
    updates = {}
    details = result.get("details", {})

    # 提取路径
    paths = details.get("paths", [])
    if paths:
        existing_paths = state.get("discovered_paths", [])
        new_paths = [p for p in paths if p not in existing_paths]
        if new_paths:
            updates["discovered_paths"] = new_paths
            logger.info(f"[Analyzer] 发现新路径: {new_paths[:10]}")

        # 检查敏感路径
        sensitive_patterns = [
            ('admin', '管理后台'),
            ('login', '登录页面'),
            ('backup', '备份文件'),
            ('config', '配置文件'),
            ('api', 'API端点'),
            ('upload', '上传功能'),
            ('.git', 'Git泄露'),
            ('.env', '环境配置'),
            ('phpinfo', 'PHP信息泄露'),
        ]

        for path in paths:
            for pattern, desc in sensitive_patterns:
                if pattern in path.lower():
                    updates.setdefault("findings", []).append({
                        "tool": "gobuster",
                        "type": "sensitive_path",
                        "title": f"敏感路径: {path}",
                        "description": f"发现{desc}: {path}"
                    })
                    break

    return updates


def _generate_analysis_summary(result: Dict[str, Any], state: PentestState, updates: Dict[str, Any]) -> str:
    """生成分析摘要"""
    tool = result.get("tool", "unknown")
    success = result.get("success", False)

    if not success:
        return f"{tool} 执行失败: {result.get('error', 'unknown error')}"

    summary_parts = [f"{tool} 执行成功"]

    # 添加关键发现
    if updates.get("discovered_ports"):
        ports = updates["discovered_ports"][:5]
        summary_parts.append(f"发现端口: {', '.join(map(str, ports))}")

    if updates.get("discovered_paths"):
        paths = updates["discovered_paths"][:3]
        summary_parts.append(f"发现路径: {', '.join(paths)}")

    if updates.get("ctf_hints"):
        hints = updates["ctf_hints"][:3]
        summary_parts.append(f"CTF线索: {', '.join(hints)}")

    if updates.get("findings"):
        summary_parts.append(f"发现问题: {len(updates['findings'])}个")

    # 添加原始结果摘要
    if result.get("summary"):
        summary_parts.append(result["summary"])

    return " | ".join(summary_parts)


def extract_flag_from_text(text: str) -> str:
    """
    从文本中提取flag

    Args:
        text: 可能包含flag的文本

    Returns:
        找到的第一个flag，未找到返回空字符串
    """
    for pattern in FLAG_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            return matches[0]
    return ""


def check_all_flags_from_text(text: str) -> List[str]:
    """
    从文本中提取所有flag

    Args:
        text: 可能包含flag的文本

    Returns:
        找到的所有flag列表
    """
    all_flags = []
    for pattern in FLAG_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            if match not in all_flags:
                all_flags.append(match)
    return all_flags
