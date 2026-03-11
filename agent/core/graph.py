"""
LangGraph 工作流图构建
定义渗透测试的完整工作流
"""

import logging
from typing import Dict, Any, Literal

from langgraph.graph import StateGraph, END

from agent.core.state import PentestState
from agent.core.nodes.planner import planner_node
from agent.core.nodes.executor import (
    http_scan_node,
    nmap_scan_node,
    gobuster_node,
    nuclei_node,
    nikto_node
)
from agent.core.nodes.analyzer import analyzer_node

logger = logging.getLogger(__name__)


def route_after_planner(state: PentestState) -> Literal["http", "nmap", "gobuster", "nuclei", "nikto", "analyzer", "end"]:
    """
    规划节点后的路由函数

    根据next_action决定下一步执行哪个节点
    """
    next_action = state.get("next_action", "end")

    logger.debug(f"[Router] 路由到: {next_action}")

    if next_action == "end" or state.get("is_complete"):
        return "end"

    # 映射到对应的执行节点
    action_map = {
        "http": "http",
        "nmap": "nmap",
        "gobuster": "gobuster",
        "nuclei": "nuclei",
        "nikto": "nikto",
    }

    return action_map.get(next_action, "end")


def route_after_executor(state: PentestState) -> Literal["analyzer", "end"]:
    """
    执行节点后的路由函数

    执行完成后进入分析节点
    """
    # 检查是否已找到flag
    if state.get("flag_found"):
        return "end"

    # 进入分析节点
    return "analyzer"


def route_after_analyzer(state: PentestState) -> Literal["planner", "end"]:
    """
    分析节点后的路由函数

    分析完成后回到规划节点继续决策
    """
    # 检查是否完成
    if state.get("is_complete") or state.get("flag_found"):
        return "end"

    # 检查是否达到最大尝试次数
    attempts = state.get("attempts", 0)
    max_attempts = state.get("max_attempts", 10)

    if attempts >= max_attempts:
        logger.info(f"[Router] 达到最大尝试次数 {max_attempts}")
        return "end"

    # 回到规划节点继续决策
    return "planner"


def build_pentest_graph() -> StateGraph:
    """
    构建渗透测试工作流图

    图结构:
    START -> PLANNER -> [HTTP/NMAP/GOBUSTER/NUCLEI/NIKTO] -> ANALYZER -> PLANNER -> ...
                                                                              |
                                                                              v
                                                                             END

    Returns:
        编译好的StateGraph实例
    """
    logger.info("[Graph] 开始构建工作流图...")

    # 创建状态图
    workflow = StateGraph(PentestState)

    # 添加节点
    workflow.add_node("planner", planner_node)
    workflow.add_node("http", http_scan_node)
    workflow.add_node("nmap", nmap_scan_node)
    workflow.add_node("gobuster", gobuster_node)
    workflow.add_node("nuclei", nuclei_node)
    workflow.add_node("nikto", nikto_node)
    workflow.add_node("analyzer", analyzer_node)

    # 设置入口点
    workflow.set_entry_point("planner")

    # 添加条件边: 规划节点后
    workflow.add_conditional_edges(
        "planner",
        route_after_planner,
        {
            "http": "http",
            "nmap": "nmap",
            "gobuster": "gobuster",
            "nuclei": "nuclei",
            "nikto": "nikto",
            "analyzer": "analyzer",
            "end": END
        }
    )

    # 添加边: 执行节点 -> 分析节点
    workflow.add_conditional_edges("http", route_after_executor, {"analyzer": "analyzer", "end": END})
    workflow.add_conditional_edges("nmap", route_after_executor, {"analyzer": "analyzer", "end": END})
    workflow.add_conditional_edges("gobuster", route_after_executor, {"analyzer": "analyzer", "end": END})
    workflow.add_conditional_edges("nuclei", route_after_executor, {"analyzer": "analyzer", "end": END})
    workflow.add_conditional_edges("nikto", route_after_executor, {"analyzer": "analyzer", "end": END})

    # 添加条件边: 分析节点后
    workflow.add_conditional_edges(
        "analyzer",
        route_after_analyzer,
        {
            "planner": "planner",
            "end": END
        }
    )

    # 编译图
    graph = workflow.compile()

    logger.info("[Graph] 工作流图构建完成")

    return graph


def get_graph_mermaid() -> str:
    """
    获取工作流图的Mermaid图表示

    Returns:
        Mermaid格式的图描述
    """
    return """
graph TD
    START[开始] --> PLANNER[规划节点]

    PLANNER -->|HTTP| HTTP[HTTP扫描]
    PLANNER -->|NMAP| NMAP[端口扫描]
    PLANNER -->|GOBUSTER| GOBUSTER[目录枚举]
    PLANNER -->|NUCLEI| NUCLEI[漏洞扫描]
    PLANNER -->|NIKTO| NIKTO[Web扫描]
    PLANNER -->|END| END[结束]

    HTTP --> ANALYZER[分析节点]
    NMAP --> ANALYZER
    GOBUSTER --> ANALYZER
    NUCLEI --> ANALYZER
    NIKTO --> ANALYZER

    HTTP -->|找到Flag| END
    NMAP -->|找到Flag| END
    GOBUSTER -->|找到Flag| END
    NUCLEI -->|找到Flag| END
    NIKTO -->|找到Flag| END

    ANALYZER -->|继续| PLANNER
    ANALYZER -->|完成| END
"""


# 用于调试和可视化
if __name__ == "__main__":
    print("工作流图结构:")
    print(get_graph_mermaid())

    # 测试图构建
    graph = build_pentest_graph()
    print("\n图构建成功!")

    # 打印节点信息
    print("\n节点列表:")
    for node in graph.nodes:
        print(f"  - {node}")
