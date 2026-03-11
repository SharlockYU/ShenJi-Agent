"""
执行节点 - 执行各种安全工具
每个工具对应一个节点函数
"""

import time
import logging
import subprocess
import re
from typing import Dict, Any, List

from agent.core.state import PentestState
from agent.tools.http import HTTPTool
from agent.tools.nmap import NmapTool
from agent.tools.gobuster import GobusterTool
from agent.tools.nuclei import NucleiTool
from agent.tools.nikto import NiktoTool

logger = logging.getLogger(__name__)


def http_scan_node(state: PentestState) -> Dict[str, Any]:
    """
    HTTP扫描节点 - 获取网页内容并分析

    Args:
        state: 当前状态

    Returns:
        状态更新字典
    """
    logger.info("[HTTP] 开始HTTP扫描...")
    start_time = time.time()

    target = state.get("target", "")
    config = state.get("config", {})

    # 确保URL格式正确
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    try:
        # 执行HTTP请求
        http_result = HTTPTool.execute_request(target, method="GET")

        if not http_result.get("success"):
            return {
                "executed_tools": state.get("executed_tools", []) + ["http"],
                "tools_results": [{
                    "tool": "http",
                    "success": False,
                    "error": http_result.get("error", "Unknown error"),
                    "execution_time": time.time() - start_time
                }]
            }

        # 分析内容
        analyzed = HTTPTool.analyze_content(
            http_result.get("content", ""),
            http_result.get("url", target)
        )

        # 提取关键信息
        findings = []
        ctf_hints = []
        discovered_paths = []

        # 检查flag
        flags_found = analyzed.get("flags_found", [])
        flag_value = flags_found[0] if flags_found else ""

        # 提取CTF线索
        for hint in analyzed.get("ctf_hints", []):
            if isinstance(hint, dict):
                ctf_hints.append(hint.get("pattern", str(hint)))
            else:
                ctf_hints.append(str(hint))

        # 提取链接作为发现路径
        for link in analyzed.get("links", [])[:20]:
            href = link.get("href", "")
            if href and href.startswith("/"):
                discovered_paths.append(href)

        # 提取隐藏字段
        hidden_inputs = analyzed.get("hidden_inputs", [])
        if hidden_inputs:
            findings.append({
                "type": "hidden_inputs",
                "description": f"发现 {len(hidden_inputs)} 个隐藏表单字段",
                "details": hidden_inputs
            })

        # 提取HTML注释
        html_comments = analyzed.get("html_comments", [])
        if html_comments:
            findings.append({
                "type": "html_comments",
                "description": f"发现 {len(html_comments)} 个HTML注释",
                "details": html_comments[:5]
            })

        # 构建结果
        execution_time = time.time() - start_time

        result = {
            "tool": "http",
            "success": True,
            "url": http_result.get("url", target),
            "status_code": http_result.get("status_code"),
            "title": analyzed.get("title", ""),
            "content_length": http_result.get("content_length", 0),
            "execution_time": execution_time,
            "summary": f"状态码: {http_result.get('status_code')}, 标题: {analyzed.get('title', 'N/A')}, "
                      f"表单: {len(analyzed.get('forms', []))}, 链接: {len(analyzed.get('links', []))}",
            "details": {
                "forms": len(analyzed.get("forms", [])),
                "links": len(analyzed.get("links", [])),
                "scripts": len(analyzed.get("scripts", [])),
                "ctf_hints_count": len(ctf_hints)
            }
        }

        logger.info(f"[HTTP] 扫描完成，耗时 {execution_time:.2f}s")

        return {
            "executed_tools": state.get("executed_tools", []) + ["http"],
            "tools_results": [result],
            "flag_found": bool(flag_value),
            "flag_value": flag_value,
            "ctf_hints": ctf_hints,
            "discovered_paths": discovered_paths,
            "findings": findings,
            "messages": [f"[HTTP] 完成: {result['summary']}"]
        }

    except Exception as e:
        logger.error(f"[HTTP] 执行失败: {e}")
        return {
            "executed_tools": state.get("executed_tools", []) + ["http"],
            "tools_results": [{
                "tool": "http",
                "success": False,
                "error": str(e),
                "execution_time": time.time() - start_time
            }],
            "messages": [f"[HTTP] 失败: {e}"]
        }


def nmap_scan_node(state: PentestState) -> Dict[str, Any]:
    """
    Nmap扫描节点 - 端口扫描

    Args:
        state: 当前状态

    Returns:
        状态更新字典
    """
    logger.info("[Nmap] 开始端口扫描...")
    start_time = time.time()

    target_info = state.get("target_info", {})
    target = target_info.get("host", state.get("target", ""))
    config = state.get("config", {}).get("tools", {}).get("nmap", {})
    timeout = config.get("timeout", 300)

    try:
        # 构建命令
        command = NmapTool.build_command(target, {"scan_type": "-sV -sC"})

        # 执行命令
        result = _execute_command(command, timeout)

        if not result.get("success"):
            return {
                "executed_tools": state.get("executed_tools", []) + ["nmap"],
                "tools_results": [{
                    "tool": "nmap",
                    "success": False,
                    "error": result.get("error", "Command execution failed"),
                    "execution_time": time.time() - start_time
                }]
            }

        # 解析输出
        output = result.get("output", "")
        findings = NmapTool.parse_output(output)

        # 提取开放端口
        discovered_ports = []
        for finding in findings:
            if finding.metadata.get("port"):
                discovered_ports.append(finding.metadata["port"])

        execution_time = time.time() - start_time

        result_data = {
            "tool": "nmap",
            "success": True,
            "command": command,
            "output_length": len(output),
            "execution_time": execution_time,
            "summary": f"发现 {len(discovered_ports)} 个开放端口: {', '.join(map(str, discovered_ports[:10]))}",
            "details": {
                "open_ports": discovered_ports,
                "findings_count": len(findings)
            }
        }

        logger.info(f"[Nmap] 扫描完成，发现 {len(discovered_ports)} 个端口，耗时 {execution_time:.2f}s")

        return {
            "executed_tools": state.get("executed_tools", []) + ["nmap"],
            "tools_results": [result_data],
            "discovered_ports": discovered_ports,
            "findings": [{"tool": "nmap", "title": f.title, "description": f.description} for f in findings],
            "messages": [f"[Nmap] 完成: {result_data['summary']}"]
        }

    except Exception as e:
        logger.error(f"[Nmap] 执行失败: {e}")
        return {
            "executed_tools": state.get("executed_tools", []) + ["nmap"],
            "tools_results": [{
                "tool": "nmap",
                "success": False,
                "error": str(e),
                "execution_time": time.time() - start_time
            }],
            "messages": [f"[Nmap] 失败: {e}"]
        }


def gobuster_node(state: PentestState) -> Dict[str, Any]:
    """
    Gobuster节点 - 目录枚举

    Args:
        state: 当前状态

    Returns:
        状态更新字典
    """
    logger.info("[Gobuster] 开始目录枚举...")
    start_time = time.time()

    target = state.get("target", "")
    config = state.get("config", {}).get("tools", {}).get("gobuster", {})
    timeout = config.get("timeout", 600)

    # 确保URL格式
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    try:
        # 构建命令
        command = GobusterTool.build_command(target, {
            "wordlist": config.get("wordlist", "./data/wordlists/common.txt"),
            "threads": config.get("threads", 10)
        })

        # 执行命令
        result = _execute_command(command, timeout)

        if not result.get("success"):
            return {
                "executed_tools": state.get("executed_tools", []) + ["gobuster"],
                "tools_results": [{
                    "tool": "gobuster",
                    "success": False,
                    "error": result.get("error", "Command execution failed"),
                    "execution_time": time.time() - start_time
                }]
            }

        # 解析输出
        output = result.get("output", "")
        findings = GobusterTool.parse_output(output)

        # 提取发现的路径
        discovered_paths = []
        for finding in findings:
            if finding.metadata.get("path"):
                discovered_paths.append(finding.metadata["path"])

        execution_time = time.time() - start_time

        result_data = {
            "tool": "gobuster",
            "success": True,
            "command": command,
            "output_length": len(output),
            "execution_time": execution_time,
            "summary": f"发现 {len(discovered_paths)} 个有效路径",
            "details": {
                "paths": discovered_paths[:50],
                "findings_count": len(findings)
            }
        }

        logger.info(f"[Gobuster] 枚举完成，发现 {len(discovered_paths)} 个路径，耗时 {execution_time:.2f}s")

        return {
            "executed_tools": state.get("executed_tools", []) + ["gobuster"],
            "tools_results": [result_data],
            "discovered_paths": discovered_paths,
            "findings": [{"tool": "gobuster", "title": f.title, "description": f.description} for f in findings],
            "messages": [f"[Gobuster] 完成: {result_data['summary']}"]
        }

    except Exception as e:
        logger.error(f"[Gobuster] 执行失败: {e}")
        return {
            "executed_tools": state.get("executed_tools", []) + ["gobuster"],
            "tools_results": [{
                "tool": "gobuster",
                "success": False,
                "error": str(e),
                "execution_time": time.time() - start_time
            }],
            "messages": [f"[Gobuster] 失败: {e}"]
        }


def nuclei_node(state: PentestState) -> Dict[str, Any]:
    """
    Nuclei节点 - 漏洞扫描

    Args:
        state: 当前状态

    Returns:
        状态更新字典
    """
    logger.info("[Nuclei] 开始漏洞扫描...")
    start_time = time.time()

    target = state.get("target", "")
    config = state.get("config", {}).get("tools", {}).get("nuclei", {})
    timeout = config.get("timeout", 600)

    # 确保URL格式
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    try:
        # 构建命令
        command = NucleiTool.build_command(target, {
            "templates": config.get("templates", "default")
        })

        # 执行命令
        result = _execute_command(command, timeout)

        if not result.get("success"):
            return {
                "executed_tools": state.get("executed_tools", []) + ["nuclei"],
                "tools_results": [{
                    "tool": "nuclei",
                    "success": False,
                    "error": result.get("error", "Command execution failed"),
                    "execution_time": time.time() - start_time
                }]
            }

        # 解析输出
        output = result.get("output", "")
        findings = NucleiTool.parse_output(output)

        # 提取漏洞信息
        discovered_vulns = []
        for finding in findings:
            discovered_vulns.append({
                "title": finding.title,
                "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                "description": finding.description
            })

        execution_time = time.time() - start_time

        result_data = {
            "tool": "nuclei",
            "success": True,
            "command": command,
            "output_length": len(output),
            "execution_time": execution_time,
            "summary": f"发现 {len(discovered_vulns)} 个漏洞/问题",
            "details": {
                "vulnerabilities": discovered_vulns,
                "findings_count": len(findings)
            }
        }

        logger.info(f"[Nuclei] 扫描完成，发现 {len(discovered_vulns)} 个问题，耗时 {execution_time:.2f}s")

        return {
            "executed_tools": state.get("executed_tools", []) + ["nuclei"],
            "tools_results": [result_data],
            "discovered_vulns": discovered_vulns,
            "findings": [{"tool": "nuclei", "title": f.title, "description": f.description} for f in findings],
            "messages": [f"[Nuclei] 完成: {result_data['summary']}"]
        }

    except Exception as e:
        logger.error(f"[Nuclei] 执行失败: {e}")
        return {
            "executed_tools": state.get("executed_tools", []) + ["nuclei"],
            "tools_results": [{
                "tool": "nuclei",
                "success": False,
                "error": str(e),
                "execution_time": time.time() - start_time
            }],
            "messages": [f"[Nuclei] 失败: {e}"]
        }


def nikto_node(state: PentestState) -> Dict[str, Any]:
    """
    Nikto节点 - Web服务器扫描

    Args:
        state: 当前状态

    Returns:
        状态更新字典
    """
    logger.info("[Nikto] 开始Web服务器扫描...")
    start_time = time.time()

    target = state.get("target", "")
    config = state.get("config", {}).get("tools", {}).get("nikto", {})
    timeout = config.get("timeout", 600)

    # 确保URL格式
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    try:
        # 构建命令
        command = NiktoTool.build_command(target, {})

        # 执行命令
        result = _execute_command(command, timeout)

        if not result.get("success"):
            return {
                "executed_tools": state.get("executed_tools", []) + ["nikto"],
                "tools_results": [{
                    "tool": "nikto",
                    "success": False,
                    "error": result.get("error", "Command execution failed"),
                    "execution_time": time.time() - start_time
                }]
            }

        # 解析输出
        output = result.get("output", "")
        findings = NiktoTool.parse_output(output)

        # 提取发现的问题
        discovered_vulns = []
        for finding in findings:
            discovered_vulns.append({
                "title": finding.title,
                "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                "description": finding.description
            })

        execution_time = time.time() - start_time

        result_data = {
            "tool": "nikto",
            "success": True,
            "command": command,
            "output_length": len(output),
            "execution_time": execution_time,
            "summary": f"发现 {len(discovered_vulns)} 个服务器配置问题",
            "details": {
                "issues": discovered_vulns[:20],
                "findings_count": len(findings)
            }
        }

        logger.info(f"[Nikto] 扫描完成，发现 {len(discovered_vulns)} 个问题，耗时 {execution_time:.2f}s")

        return {
            "executed_tools": state.get("executed_tools", []) + ["nikto"],
            "tools_results": [result_data],
            "discovered_vulns": discovered_vulns,
            "findings": [{"tool": "nikto", "title": f.title, "description": f.description} for f in findings],
            "messages": [f"[Nikto] 完成: {result_data['summary']}"]
        }

    except Exception as e:
        logger.error(f"[Nikto] 执行失败: {e}")
        return {
            "executed_tools": state.get("executed_tools", []) + ["nikto"],
            "tools_results": [{
                "tool": "nikto",
                "success": False,
                "error": str(e),
                "execution_time": time.time() - start_time
            }],
            "messages": [f"[Nikto] 失败: {e}"]
        }


def _execute_command(command: str, timeout: int = 300) -> Dict[str, Any]:
    """
    执行shell命令

    Args:
        command: 命令字符串
        timeout: 超时时间(秒)

    Returns:
        执行结果字典
    """
    try:
        logger.debug(f"执行命令: {command}")

        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        output = result.stdout + result.stderr

        return {
            "success": result.returncode == 0,
            "output": output,
            "returncode": result.returncode
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"命令执行超时 ({timeout}秒)"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
