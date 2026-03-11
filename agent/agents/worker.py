"""
工作Agent基类 - 负责执行具体任务
"""

import time
from typing import Optional, Dict, Any
from datetime import datetime

from agent.agents.base import (
    BaseAgent, AgentRole, AgentStatus, AgentMessage, AgentTask
)
from agent.core.models import ToolResult
from agent.core.executor import ToolExecutor


class WorkerAgent(BaseAgent):
    """
    工作Agent基类
    
    所有执行具体任务的工作Agent都继承此类
    """
    
    def __init__(
        self,
        agent_id: str,
        role: AgentRole,
        tools: list,
        config: Optional[Dict[str, Any]] = None
    ):
        super().__init__(agent_id, role, config)
        self.tools = tools  # 该Agent可以使用的工具列表
        self.executor = ToolExecutor(config.get("tools", {}) if config else {})
        self._current_task: Optional[AgentTask] = None
    
    def initialize(self) -> bool:
        """
        初始化Agent
        
        基类提供默认实现，子类可以覆盖
        """
        self._log(f"{self.role.value}Agent初始化完成", "success")
        return True
        
    def handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理收到的消息"""
        if message.message_type == "task_assignment":
            # 收到任务分配
            return self._handle_task_assignment(message)
        elif message.message_type == "task_cancel":
            # 任务取消
            return self._handle_task_cancel(message)
        elif message.message_type == "status_check":
            # 状态检查
            return self._handle_status_check(message)
        return None
    
    def _handle_task_assignment(self, message: AgentMessage) -> AgentMessage:
        """处理任务分配"""
        task_data = message.content.get("task")
        if task_data:
            # 将字典转换为AgentTask对象
            if isinstance(task_data, dict):
                task = AgentTask(**task_data)
            else:
                task = task_data
            
            # 检查是否可以执行该任务
            if task.tool not in self.tools:
                return AgentMessage(
                    from_agent=self.name,
                    to_agent=message.from_agent,
                    message_type="task_rejected",
                    content={
                        "task_id": task.id,
                        "reason": f"不支持的工具: {task.tool}"
                    }
                )
            
            # 添加任务到队列
            self.add_task(task)
            
            return AgentMessage(
                from_agent=self.name,
                to_agent=message.from_agent,
                message_type="task_accepted",
                content={
                    "task_id": task.id,
                    "status": "accepted"
                }
            )
        return None
    
    def _handle_task_cancel(self, message: AgentMessage) -> AgentMessage:
        """处理任务取消"""
        task_id = message.content.get("task_id")
        if task_id:
            # 从队列中移除任务
            for task in self._task_queue:
                if task.id == task_id:
                    self._task_queue.remove(task)
                    self._log(f"任务已取消: {task.name}")
                    break
        
        return AgentMessage(
            from_agent=self.name,
            to_agent=message.from_agent,
            message_type="task_cancelled",
            content={"task_id": task_id}
        )
    
    def _handle_status_check(self, message: AgentMessage) -> AgentMessage:
        """处理状态检查"""
        return AgentMessage(
            from_agent=self.name,
            to_agent=message.from_agent,
            message_type="status_report",
            content={
                "status": self.status.value,
                "current_task": self._current_task.name if self._current_task else None,
                "pending_tasks": len([t for t in self._task_queue if t.status == "pending"]),
                "completed_tasks": len(self._completed_tasks)
            }
        )
    
    def execute_task(self, task: AgentTask) -> ToolResult:
        """执行任务"""
        self.status = AgentStatus.WORKING
        self._current_task = task
        task.status = "running"
        task.started_at = datetime.now()
        
        self._log(f"开始执行任务: {task.name}")
        
        try:
            # 执行前置检查
            pre_check = self.pre_execute(task)
            if not pre_check.get("can_execute", True):
                result = ToolResult(
                    success=False,
                    error=pre_check.get("reason", "前置检查失败")
                )
            else:
                # 执行任务
                result = self.do_execute(task)
                
                # 执行后处理
                result = self.post_execute(task, result)
            
            # 更新任务状态
            if result.success:
                self.complete_task(task, result)
                self._log(f"任务完成: {task.name}", "success")
            else:
                task.status = "failed"
                self._log(f"任务失败: {task.name} - {result.error}", "error")
            
            return result
            
        except Exception as e:
            self._log(f"任务执行异常: {e}", "error")
            result = ToolResult(
                success=False,
                error=str(e)
            )
            task.status = "failed"
            return result
            
        finally:
            self.status = AgentStatus.IDLE
            self._current_task = None
    
    def pre_execute(self, task: AgentTask) -> Dict[str, Any]:
        """
        执行前检查
        
        Returns:
            包含 can_execute 和 reason 的字典
        """
        # 检查工具是否可用
        if task.tool not in self.tools:
            return {
                "can_execute": False,
                "reason": f"该Agent不支持工具: {task.tool}"
            }
        
        # 检查工具是否安装
        if not self.executor.is_tool_available(task.tool):
            # 对于内置工具（如http），不需要检查
            if task.tool not in ["http"]:
                return {
                    "can_execute": False,
                    "reason": f"工具未安装: {task.tool}"
                }
        
        return {"can_execute": True}
    
    def do_execute(self, task: AgentTask) -> ToolResult:
        """执行具体任务 - 子类实现"""
        # 获取超时配置
        tool_config = self.config.get("tools", {}).get(task.tool, {})
        timeout = tool_config.get("timeout", 300)
        
        # 执行命令
        result = self.executor.execute(
            task.command,
            timeout=timeout,
            show_progress=True,
            progress_text=task.name
        )
        
        return result
    
    def post_execute(self, task: AgentTask, result: ToolResult) -> ToolResult:
        """执行后处理"""
        # 基类不做额外处理，子类可以覆盖
        return result
    
    def report_completion(self, task: AgentTask, result: ToolResult) -> AgentMessage:
        """报告任务完成"""
        return AgentMessage(
            from_agent=self.name,
            to_agent="master_main",
            message_type="task_completed",
            content={
                "task": task.dict(),
                "result": result.dict()
            }
        )
    
    def report_failure(self, task: AgentTask, error: str) -> AgentMessage:
        """报告任务失败"""
        return AgentMessage(
            from_agent=self.name,
            to_agent="master_main",
            message_type="task_failed",
            content={
                "task": task.dict(),
                "error": error
            }
        )
    
    def report_finding(self, finding: Dict[str, Any]) -> AgentMessage:
        """报告发现"""
        return AgentMessage(
            from_agent=self.name,
            to_agent="master_main",
            message_type="finding_report",
            content={"finding": finding}
        )
    
    def get_capabilities(self) -> Dict[str, Any]:
        """获取Agent能力描述"""
        return {
            "agent_id": self.agent_id,
            "role": self.role.value,
            "status": self.status.value,
            "tools": self.tools,
            "pending_tasks": len([t for t in self._task_queue if t.status == "pending"]),
            "description": f"工作Agent - 支持: {', '.join(self.tools)}"
        }
