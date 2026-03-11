"""
神机 (ShenJi) - 智能渗透测试 Agent
基于 LangGraph 的持续推理循环和动态工具选择
"""

import os
import sys
import uuid
import yaml
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.live import Live
from rich.layout import Layout

from loguru import logger

from agent.core.state import PentestState, create_initial_state, state_to_dict
from agent.core.graph import build_pentest_graph
from agent.core.models import TargetInfo


class ShenJiAgent:
    """
    神机 - 基于 LangGraph 的智能渗透测试 Agent

    特性:
    - 持续推理循环: 每次工具执行后都能重新分析决策
    - 状态累积: 所有结果参与后续决策
    - 条件分支: 根据结果智能选择下一步
    - 自动停止: 找到flag或完成目标时停止
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化Agent

        Args:
            config: 配置字典，包含LLM、工具等配置
        """
        self.console = Console()
        self.config = config or self._load_default_config()
        self.graph = None

        # 配置日志
        self._setup_logging()

        # 构建工作流图
        logger.info("初始化神机 Agent...")

    def _load_default_config(self) -> Dict[str, Any]:
        """加载默认配置"""
        config = {}

        # 尝试加载配置文件
        config_paths = ["config.yaml", "config.cfg"]
        for config_path in config_paths:
            if os.path.exists(config_path):
                try:
                    if config_path.endswith(".yaml"):
                        with open(config_path, "r", encoding="utf-8") as f:
                            config = yaml.safe_load(f) or {}
                    else:
                        import configparser
                        cfg = configparser.ConfigParser()
                        cfg.read(config_path, encoding="utf-8")
                        config = {s: dict(cfg[s]) for s in cfg.sections()}
                    logger.info(f"已加载配置文件: {config_path}")
                    break
                except Exception as e:
                    logger.warning(f"加载配置文件失败: {e}")

        # 设置默认值
        if "max_attempts" not in config:
            config["max_attempts"] = 10

        return config

    def _setup_logging(self) -> None:
        """配置日志系统"""
        log_config = self.config.get("logging", {})
        log_file = log_config.get("file", "./output/logs/smart_agent.log")

        # 确保日志目录存在
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        # 配置loguru
        logger.remove()
        logger.add(
            sys.stderr,
            level=log_config.get("level", "INFO"),
            format=log_config.get("format", "{time} | {level} | {message}")
        )
        if log_file:
            logger.add(
                log_file,
                rotation=log_config.get("rotation", "10 MB"),
                retention=log_config.get("retention", "7 days"),
                level="DEBUG"
            )

    def run(self, target: str, auto_mode: bool = False) -> Dict[str, Any]:
        """
        执行渗透测试

        Args:
            target: 目标地址 (URL, IP, 或 domain:port)
            auto_mode: 是否自动模式（不需要用户确认）

        Returns:
            测试结果摘要
        """
        # 显示欢迎信息
        self._show_welcome(target)

        # 构建工作流图
        self.console.print("\n[cyan]正在构建工作流图...[/]")
        self.graph = build_pentest_graph()
        self.console.print("[green]✓ 工作流图构建完成[/]\n")

        # 创建初始状态
        initial_state = create_initial_state(target, self.config)

        # 显示初始计划
        self._display_initial_plan(target)

        # 请求确认
        if not auto_mode:
            action = Prompt.ask(
                "\n是否开始执行？",
                choices=["y", "n"],
                default="y"
            )
            if action.lower() != "y":
                self.console.print("[yellow]已取消执行[/]")
                return {"status": "cancelled"}

        # 执行工作流
        session_id = str(uuid.uuid4())[:8]
        self.console.print(f"\n[bold green]开始执行 (Session: {session_id})[/]\n")

        try:
            final_state = self._execute_workflow(initial_state)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]用户中断执行[/]")
            return {"status": "interrupted"}
        except Exception as e:
            logger.exception("执行过程中发生错误")
            self.console.print(f"\n[red]错误: {e}[/]")
            return {"status": "error", "error": str(e)}

        # 显示结果
        return self._show_summary(final_state, session_id)

    def _execute_workflow(self, initial_state: PentestState) -> PentestState:
        """
        执行工作流

        Args:
            initial_state: 初始状态

        Returns:
            最终状态
        """
        current_state = initial_state

        # 使用流式执行
        for event in self.graph.stream(current_state):
            # 处理每个节点的输出
            for node_name, node_output in event.items():
                self._handle_node_event(node_name, node_output)

                # 更新状态
                if isinstance(node_output, dict):
                    for key, value in node_output.items():
                        if isinstance(value, list) and key in current_state:
                            # 列表合并
                            existing = current_state.get(key, [])
                            if isinstance(existing, list):
                                if isinstance(value, list) and value and isinstance(value[0], type(existing[0]) if existing else object):
                                    current_state[key] = existing + [v for v in value if v not in existing]
                                else:
                                    current_state[key] = existing + value
                        else:
                            current_state[key] = value

        return current_state

    def _handle_node_event(self, node_name: str, output: Dict[str, Any]) -> None:
        """
        处理节点事件

        Args:
            node_name: 节点名称
            output: 节点输出
        """
        if not isinstance(output, dict):
            return

        # 显示节点执行信息
        if node_name == "planner":
            next_action = output.get("next_action", "unknown")
            self.console.print(f"[cyan][Planner][/cyan] 下一步: [bold]{next_action}[/]")

        elif node_name == "analyzer":
            analysis = output.get("llm_analysis", "")
            if analysis:
                self.console.print(f"[green][Analyzer][/green] {analysis[:100]}...")

            if output.get("flag_found"):
                flag = output.get("flag_value", "")
                self.console.print(f"\n[bold green]🚩🚩🚩 FLAG 已找到！🚩🚩🚩[/]")
                self.console.print(Panel(flag, title="FLAG", border_style="green", style="bold green"))

        elif node_name in ["http", "nmap", "gobuster", "nuclei", "nikto"]:
            # 获取最新的工具结果
            tools_results = output.get("tools_results", [])
            if tools_results:
                result = tools_results[-1] if isinstance(tools_results, list) else tools_results
                if isinstance(result, dict):
                    success = result.get("success", False)
                    status = "[green]✓[/]" if success else "[red]✗[/]"
                    summary = result.get("summary", "无摘要")[:50]
                    self.console.print(f"{status} [{node_name}] {summary}")

                    # 显示错误
                    if not success and result.get("error"):
                        self.console.print(f"  [red]错误: {result['error']}[/]")

        # 显示消息
        messages = output.get("messages", [])
        for msg in messages:
            self.console.print(f"[dim]{msg}[/]")

    def _show_welcome(self, target: str) -> None:
        """显示欢迎信息"""
        self.console.print(Panel(
            "[bold cyan]神机 (ShenJi)[/] v2.0.0\n"
            "[yellow]基于LangGraph的智能渗透测试Agent[/]\n"
            "[dim]「神机妙算，攻无不克」[/]\n\n"
            "[dim]特性: 持续推理 | 状态累积 | 智能选择 | 自动停止[/]\n\n"
            f"[white]目标: {target}[/]",
            title="🔮 神机 - 智能渗透测试",
            border_style="blue"
        ))

    def _display_initial_plan(self, target: str) -> None:
        """显示初始计划"""
        table = Table(title="📋 执行计划")
        table.add_column("步骤", style="cyan", width=6)
        table.add_column("节点", style="white")
        table.add_column("描述", style="dim")

        table.add_row("1", "planner", "分析目标，决定第一步工具")
        table.add_row("2", "http", "获取网页内容，分析结构")
        table.add_row("3", "analyzer", "分析HTTP结果，检测flag")
        table.add_row("4", "planner", "根据分析结果选择下一步")
        table.add_row("...", "executor", "根据LLM决策执行相应工具")
        table.add_row("...", "analyzer", "持续分析结果")
        table.add_row("N", "END", "找到flag或达到最大尝试次数")

        self.console.print(table)

    def _show_summary(self, final_state: PentestState, session_id: str) -> Dict[str, Any]:
        """
        显示执行结果摘要

        Args:
            final_state: 最终状态
            session_id: 会话ID

        Returns:
            结果摘要字典
        """
        self.console.print("\n")

        # 摘要表格
        summary_table = Table(title="📊 执行结果摘要")
        summary_table.add_column("项目", style="cyan")
        summary_table.add_column("值", style="white")

        is_complete = final_state.get("is_complete", False)
        flag_found = final_state.get("flag_found", False)
        flag_value = final_state.get("flag_value", "")
        attempts = final_state.get("attempts", 0)
        executed_tools = final_state.get("executed_tools", [])
        discovered_ports = final_state.get("discovered_ports", [])
        discovered_paths = final_state.get("discovered_paths", [])
        findings = final_state.get("findings", [])

        status = "完成" if is_complete else "未完成"
        if flag_found:
            status = "[bold green]完成 (Flag已找到)[/]"

        summary_table.add_row("状态", status)
        summary_table.add_row("会话ID", session_id)
        summary_table.add_row("尝试次数", str(attempts))
        summary_table.add_row("执行工具", ", ".join(executed_tools) or "无")
        summary_table.add_row("发现端口", ", ".join(map(str, discovered_ports[:10])) or "无")
        summary_table.add_row("发现路径", f"{len(discovered_paths)} 个")
        summary_table.add_row("发现问题", f"{len(findings)} 个")

        self.console.print(summary_table)

        # 显示Flag
        if flag_found and flag_value:
            self.console.print(f"\n[bold green]🚩🚩🚩 FLAG 🚩🚩🚩[/]")
            self.console.print(Panel(
                flag_value,
                title="🚩 FLAG",
                border_style="green",
                style="bold green",
                expand=False
            ))

        # 显示发现的问题
        if findings:
            findings_table = Table(title="🔍 发现的问题")
            findings_table.add_column("#", width=4)
            findings_table.add_column("来源", style="cyan")
            findings_table.add_column("标题", style="white")

            for i, finding in enumerate(findings[:20], 1):
                findings_table.add_row(
                    str(i),
                    finding.get("tool", "unknown"),
                    finding.get("title", str(finding))[:50]
                )

            self.console.print("\n")
            self.console.print(findings_table)

        # 返回结果
        return {
            "status": "completed" if is_complete else "incomplete",
            "session_id": session_id,
            "flag_found": flag_found,
            "flag_value": flag_value,
            "attempts": attempts,
            "executed_tools": executed_tools,
            "discovered_ports": list(discovered_ports),
            "discovered_paths": list(discovered_paths),
            "findings_count": len(findings),
            "complete_reason": final_state.get("complete_reason", "")
        }


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description="神机 (ShenJi) - 智能渗透测试 Agent")
    parser.add_argument("target", help="目标地址 (URL, IP, 或 domain:port)")
    parser.add_argument("--auto", "-a", action="store_true", help="自动模式，无需用户确认")
    parser.add_argument("--config", "-c", default="config.yaml", help="配置文件路径")
    parser.add_argument("--max-attempts", "-m", type=int, default=10, help="最大尝试次数")

    args = parser.parse_args()

    # 加载配置
    config = {}
    if os.path.exists(args.config):
        with open(args.config, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

    config["max_attempts"] = args.max_attempts

    # 创建并运行Agent
    agent = ShenJiAgent(config)
    result = agent.run(args.target, auto_mode=args.auto)

    # 打印最终状态
    print(f"\n最终状态: {result['status']}")
    if result.get("flag_found"):
        print(f"FLAG: {result['flag_value']}")


if __name__ == "__main__":
    main()
