"""
侦察Agent - 负责信息收集和HTTP分析
"""

import time
from typing import Optional, Dict, Any

from agent.agents.base import AgentRole, AgentTask
from agent.agents.worker import WorkerAgent
from agent.core.models import ToolResult
from agent.tools.http import HTTPTool, parse_http_command


class ReconAgent(WorkerAgent):
    """
    侦察Agent
    
    职责：
    1. HTTP请求和网页内容获取
    2. 网页结构分析
    3. CTF线索发现
    4. 信息收集
    """
    
    def __init__(self, agent_id: str = "1", config: Optional[Dict[str, Any]] = None):
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.RECON,
            tools=["http"],  # 侦察工具
            config=config
        )
    
    def do_execute(self, task: AgentTask) -> ToolResult:
        """执行侦察任务"""
        if task.tool == "http":
            return self._execute_http_task(task)
        else:
            return super().do_execute(task)
    
    def _execute_http_task(self, task: AgentTask) -> ToolResult:
        """执行HTTP分析任务"""
        start_time = time.time()

        try:
            # 优先从命令中解析完整URL
            parsed = parse_http_command(task.command)

            if "error" not in parsed and parsed.get("url"):
                # 使用命令中解析出的URL
                target = parsed["url"]
                method = parsed.get("method", "GET")
                data = parsed.get("data")
                data_format = parsed.get("data_format")
            else:
                # 回退到使用 task.target
                target = str(task.target)
                method = "GET"
                data = None
                data_format = None

            # 确保URL有协议前缀
            if not target.startswith(('http://', 'https://')):
                target = f"http://{target}"

            self._log(f"正在获取网页内容: {target}")

            # 使用HTTP工具获取网页内容
            if data:
                http_result = HTTPTool.execute_request(
                    url=target,
                    method=method,
                    data=data,
                    data_format=data_format or "json"
                )
            else:
                http_result = HTTPTool.fetch_page(target)
            
            if "error" in http_result:
                return ToolResult(
                    success=False,
                    error=http_result["error"],
                    execution_time=time.time() - start_time
                )
            
            # 分析网页内容
            self._log("正在分析网页内容...")
            analyzed = HTTPTool.analyze_content(
                http_result.get("raw_content", ""),
                target
            )
            
            # 构建结果输出
            output_lines = [
                f"URL: {http_result.get('url', target)}",
                f"状态码: {http_result.get('status_code', 'N/A')}",
                f"标题: {analyzed.get('title', 'N/A')}",
                "",
                "=== 页面信息 ===",
                f"表单数量: {len(analyzed.get('forms', []))}",
                f"链接数量: {len(analyzed.get('links', []))}",
                f"脚本数量: {len(analyzed.get('scripts', []))}",
            ]
            
            # CTF线索
            if analyzed.get("ctf_hints"):
                output_lines.append("")
                output_lines.append("=== CTF线索 ===")
                for hint in analyzed["ctf_hints"]:
                    output_lines.append(f"  - 发现关键词: {hint['pattern']}")
            
            # 检查是否发现flag
            flags_found = analyzed.get("flags_found", [])
            if flags_found:
                output_lines.append("")
                output_lines.append("=== 🚩 FLAG 发现 ===")
                for flag in flags_found:
                    output_lines.append(f"  {flag}")
            
            output = "\n".join(output_lines)
            
            return ToolResult(
                success=True,
                output=output,
                execution_time=time.time() - start_time,
                parsed_data={
                    "http_result": http_result,
                    "analyzed": analyzed,
                    "flags_found": flags_found
                }
            )
            
        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                execution_time=time.time() - start_time
            )
    
    def post_execute(self, task: AgentTask, result: ToolResult) -> ToolResult:
        """执行后处理"""
        if result.success and result.parsed_data:
            # 检查是否有CTF线索
            analyzed = result.parsed_data.get("analyzed", {})
            ctf_hints = analyzed.get("ctf_hints", [])
            
            if ctf_hints:
                self._log(f"发现 {len(ctf_hints)} 个CTF线索", "warning")
            
            # 检查是否有flag
            flags = result.parsed_data.get("flags_found", [])
            if flags:
                self._log(f"🚩 发现 {len(flags)} 个FLAG!", "success")
        
        return result
    
    def get_capabilities(self) -> Dict[str, Any]:
        """获取能力描述"""
        return {
            "agent_id": self.agent_id,
            "role": self.role.value,
            "status": self.status.value,
            "tools": self.tools,
            "capabilities": [
                "HTTP请求发送",
                "网页内容获取",
                "页面结构分析",
                "CTF线索发现",
                "表单和链接提取"
            ],
            "description": "侦察Agent - 负责信息收集和HTTP分析"
        }
