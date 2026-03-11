"""
LLM 模块 - 大语言模型接口
"""

import os
import configparser
from typing import Optional, Dict, Any
from pathlib import Path

from langchain_openai import ChatOpenAI


class LLMProvider:
    """LLM 提供者基类"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.provider_type = self.config.get("provider", "openai")
        self.llm = None
        self._cfg_config = None  # 缓存 config.cfg 内容
    
    def _load_config_cfg(self) -> configparser.ConfigParser:
        """加载 config.cfg 文件"""
        if self._cfg_config is not None:
            return self._cfg_config
        
        cfg = configparser.ConfigParser()
        
        # 查找 config.cfg 文件
        config_paths = [
            Path("config.cfg"),
            Path(__file__).parent.parent.parent / "config.cfg",  # 项目根目录
        ]
        
        for config_path in config_paths:
            if config_path.exists():
                cfg.read(config_path, encoding="utf-8")
                self._cfg_config = cfg
                return cfg
        
        return cfg
    
    def _get_openai_config(self, key: str, default: str = None) -> Optional[str]:
        """从 config.cfg 获取 OpenAI 配置"""
        cfg = self._load_config_cfg()
        
        # 优先从 openai section 读取
        if cfg.has_option("openai", key):
            return cfg.get("openai", key)
        
        return default
    
    def initialize(self) -> None:
        """初始化 LLM"""
        if self.provider_type == "openai":
            # 优先级: config.cfg > 代码传入配置 > 环境变量
            model = self._get_openai_config("model") or \
                    self.config.get("model") or \
                    "gpt-4-turbo-preview"
            temperature = float(self.config.get("temperature", 0))
            
            # API Key: config.cfg > 环境变量
            api_key = self._get_openai_config("api_key") or \
                     os.getenv("OPENAI_API_KEY")
            
            # Base URL: config.cfg > 代码传入配置 > 环境变量
            base_url = self._get_openai_config("base_url") or \
                       self.config.get("base_url") or \
                       os.getenv("OPENAI_BASE_URL")
            
            if not api_key:
                raise ValueError("未配置 OpenAI API Key。请在 config.cfg 的 [openai] section 中设置 api_key，或设置 OPENAI_API_KEY 环境变量。")
            
            # 构建 ChatOpenAI 参数
            llm_kwargs = {
                "model": model,
                "temperature": temperature,
                "api_key": api_key,
            }
            
            if base_url:
                llm_kwargs["base_url"] = base_url
            
            # 调试输出
            print(f"[DEBUG] LLM 配置:")
            print(f"  - model: {model}")
            print(f"  - base_url: {base_url}")
            print(f"  - api_key: {api_key[:20]}..." if api_key else "  - api_key: None")
            
            self.llm = ChatOpenAI(**llm_kwargs)
        else:
            raise ValueError(f"不支持的 LLM 提供者: {self.provider_type}")
    
    def generate(self, prompt: str) -> str:
        """生成文本"""
        if not self.llm:
            raise RuntimeError("LLM 未初始化")
        
        response = self.llm.invoke(prompt)
        return response.content
    
    def generate_with_context(self, prompt: str, context: str) -> str:
        """带上下文生成"""
        full_prompt = f"{context}\n\n{prompt}"
        return self.generate(full_prompt)
    
    def get_model(self):
        """获取模型实例"""
        return self.llm
