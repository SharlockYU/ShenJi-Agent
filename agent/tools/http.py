"""
HTTP 请求工具 - 改进版
支持多种请求方式和数据格式，带Session复用、重试机制、代理支持
"""

import re
import json
import time
import logging
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from functools import wraps
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from xml.etree import ElementTree as ET

from agent.tools.base import BaseTool, ToolInfo
from agent.core.models import RiskLevel, Finding, ToolResult

# 配置日志
logger = logging.getLogger(__name__)


@dataclass
class HTTPConfig:
    """HTTP配置类"""
    timeout: int = 10
    max_retries: int = 3
    retry_delay: float = 1.0
    backoff_factor: float = 0.5
    follow_redirects: bool = True
    verify_ssl: bool = True
    proxies: Optional[Dict[str, str]] = None
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    default_headers: Dict[str, str] = field(default_factory=lambda: {"Accept": "*/*"})
    # 重试状态码
    retry_status_codes: List[int] = field(default_factory=lambda: [429, 500, 502, 503, 504])


class HTTPTool(BaseTool):
    """HTTP 请求工具 - 改进版，支持Session复用、重试、代理"""

    # 支持的HTTP方法
    SUPPORTED_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

    # 支持的内容类型
    CONTENT_TYPES = {
        "json": "application/json",
        "xml": "application/xml",
        "form": "application/x-www-form-urlencoded",
        "multipart": "multipart/form-data",
        "text": "text/plain",
        "html": "text/html"
    }

    # Session实例（类级别，支持连接复用）
    _session: Optional[requests.Session] = None
    _config: HTTPConfig = HTTPConfig()

    @classmethod
    def get_info(cls) -> ToolInfo:
        return ToolInfo(
            name="http",
            description="HTTP 请求工具，支持多种请求方式(GET/POST/PUT/DELETE等)和数据格式(JSON/XML/Form等)",
            risk_level=RiskLevel.LOW,
            category="reconnaissance",
            examples=[
                "http get http://example.com",
                "http post http://api.example.com json '{\"key\":\"value\"}'",
                "http post http://example.com/form form 'username=admin&password=test'",
                "http put http://api.example.com/1 xml '<data><name>test</name></data>'",
                "http delete http://api.example.com/1"
            ],
            options={
                "method": f"HTTP方法: {', '.join(cls.SUPPORTED_METHODS)}",
                "data_format": "数据格式: json, xml, form, multipart, text",
                "data": "请求体数据",
                "headers": "自定义请求头 (JSON格式)",
                "params": "URL查询参数 (JSON格式)",
                "timeout": "请求超时时间(秒)",
                "follow_redirects": "是否跟随重定向",
                "verify_ssl": "是否验证SSL证书",
                "auth": "认证信息 (user:password)",
                "proxies": "代理配置 (如 {'http': 'http://127.0.0.1:8080'})"
            }
        )

    @classmethod
    def set_config(cls, config: HTTPConfig) -> None:
        """
        设置全局HTTP配置

        Args:
            config: HTTPConfig配置实例
        """
        cls._config = config
        cls._session = None  # 重置session以应用新配置
        logger.info(f"HTTP配置已更新: timeout={config.timeout}, max_retries={config.max_retries}")

    @classmethod
    def get_config(cls) -> HTTPConfig:
        """获取当前配置"""
        return cls._config

    @classmethod
    def _get_session(cls) -> requests.Session:
        """
        获取或创建Session（带连接池和重试策略）

        Returns:
            配置好的requests.Session实例
        """
        if cls._session is None:
            session = requests.Session()

            # 配置重试策略
            retry_strategy = Retry(
                total=cls._config.max_retries,
                backoff_factor=cls._config.backoff_factor,
                status_forcelist=cls._config.retry_status_codes,
                allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"],
                raise_on_status=False
            )

            # 挂载适配器
            adapter = HTTPAdapter(
                max_retries=retry_strategy,
                pool_connections=10,
                pool_maxsize=20
            )
            session.mount("http://", adapter)
            session.mount("https://", adapter)

            # 配置代理
            if cls._config.proxies:
                session.proxies.update(cls._config.proxies)
                logger.info(f"代理已配置: {cls._config.proxies}")

            cls._session = session
            logger.debug("HTTP Session已创建")

        return cls._session

    @classmethod
    def close(cls) -> None:
        """关闭Session，释放资源"""
        if cls._session:
            cls._session.close()
            cls._session = None
            logger.debug("HTTP Session已关闭")

    @classmethod
    def build_command(cls, target: str, options: Optional[Dict[str, Any]] = None) -> str:
        """构建命令字符串"""
        options = options or {}
        method = options.get("method", "GET").upper()
        data_format = options.get("data_format", "")
        data = options.get("data", "")

        cmd_parts = ["http", method.lower(), target]

        if data_format and data:
            cmd_parts.append(data_format)
            cmd_parts.append(f"'{data}'")

        return " ".join(cmd_parts)

    @classmethod
    def parse_output(cls, output: str) -> List[Finding]:
        """解析HTTP响应内容"""
        findings = []

        # 分析响应内容，查找CTF线索
        ctf_patterns = [
            r"flag\{.*?\}",
            r"ctf\{.*?\}",
            r"CTF\{.*?\}",
        ]

        content = output.lower()

        # 检查CTF相关关键词
        ctf_keywords = ["hidden", "secret", "password", "admin", "login", "flag", "ctf"]
        for keyword in ctf_keywords:
            if keyword in content:
                findings.append(Finding(
                    title=f"CTF线索发现: {keyword}",
                    description=f"网页内容中包含关键词 '{keyword}'，可能是CTF挑战的线索",
                    severity=RiskLevel.LOW,
                    tool="http",
                    raw_output=output[:200],
                    metadata={"keyword": keyword}
                ))
                break

        # 检查HTTP状态码
        if "200" in output or "OK" in output:
            findings.append(Finding(
                title="HTTP 200 OK",
                description="目标URL可正常访问",
                severity=RiskLevel.LOW,
                tool="http",
                raw_output=output[:100],
                metadata={"status_code": 200}
            ))

        return findings

    @classmethod
    def execute_request(
        cls,
        url: str,
        method: str = "GET",
        data: Optional[Any] = None,
        data_format: str = "json",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        follow_redirects: Optional[bool] = None,
        verify_ssl: Optional[bool] = None,
        auth: Optional[tuple] = None,
        cookies: Optional[Dict[str, str]] = None,
        proxies: Optional[Dict[str, str]] = None,
        allow_retry: bool = True
    ) -> Dict[str, Any]:
        """
        执行HTTP请求（改进版）

        Args:
            url: 目标URL
            method: HTTP方法 (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
            data: 请求体数据
            data_format: 数据格式 (json, xml, form, multipart, text)
            headers: 自定义请求头
            params: URL查询参数
            timeout: 请求超时时间(秒)，None使用配置默认值
            follow_redirects: 是否跟随重定向，None使用配置默认值
            verify_ssl: 是否验证SSL证书，None使用配置默认值
            auth: 认证信息 (username, password)
            cookies: Cookie字典
            proxies: 本次请求的代理配置
            allow_retry: 是否允许重试（内部使用）

        Returns:
            包含响应信息的字典，格式统一为:
            {
                "success": bool,
                "status_code": int,
                "content": str,  # 统一的响应内容键
                "raw_content": str,  # 向后兼容
                ...
            }
        """
        # 使用配置默认值
        timeout = timeout if timeout is not None else cls._config.timeout
        follow_redirects = follow_redirects if follow_redirects is not None else cls._config.follow_redirects
        verify_ssl = verify_ssl if verify_ssl is not None else cls._config.verify_ssl

        method = method.upper()

        if method not in cls.SUPPORTED_METHODS:
            return {"success": False, "error": f"不支持的HTTP方法: {method}. 支持的方法: {', '.join(cls.SUPPORTED_METHODS)}"}

        # 构建请求头
        request_headers = {
            "User-Agent": cls._config.user_agent,
            **cls._config.default_headers
        }
        if headers:
            request_headers.update(headers)

        # 根据数据格式设置Content-Type和处理数据
        request_body = None
        if data is not None:
            content_type = cls.CONTENT_TYPES.get(data_format.lower(), "application/json")
            request_headers["Content-Type"] = content_type
            request_body = cls._prepare_request_body(data, data_format)

        # 合并代理配置
        request_proxies = cls._config.proxies.copy() if cls._config.proxies else {}
        if proxies:
            request_proxies.update(proxies)

        try:
            session = cls._get_session()
            start_time = time.time()

            # 记录请求日志
            logger.info(f"HTTP {method} {url}")

            response = session.request(
                method=method,
                url=url,
                headers=request_headers,
                params=params,
                data=request_body,
                timeout=timeout,
                allow_redirects=follow_redirects,
                verify=verify_ssl,
                auth=auth,
                cookies=cookies,
                proxies=request_proxies if request_proxies else None
            )

            elapsed_time = time.time() - start_time

            # 尝试解析响应内容
            response_data = cls._parse_response(response)

            result = {
                "success": True,
                "status_code": response.status_code,
                "reason": response.reason,
                "headers": dict(response.headers),
                "cookies": dict(response.cookies),
                "url": response.url,
                "elapsed_time": round(elapsed_time, 3),
                "content_type": response.headers.get("Content-Type", ""),
                "content": response.text,  # 统一使用 content 键
                "raw_content": response.text,  # 向后兼容
                "content_length": len(response.content),
                **response_data
            }

            logger.debug(f"HTTP {method} {url} -> {response.status_code} ({elapsed_time:.3f}s)")

            return result

        except requests.exceptions.Timeout:
            error_msg = f"请求超时 ({timeout}秒)"
            logger.warning(f"HTTP {method} {url} -> {error_msg}")
            return {"success": False, "error": error_msg}

        except requests.exceptions.SSLError as e:
            error_msg = f"SSL错误: {str(e)}"
            logger.warning(f"HTTP {method} {url} -> {error_msg}")
            return {"success": False, "error": error_msg}

        except requests.exceptions.ConnectionError as e:
            error_msg = f"连接错误: {str(e)}"
            logger.warning(f"HTTP {method} {url} -> {error_msg}")

            # 手动重试（针对连接错误）
            if allow_retry and cls._config.max_retries > 0:
                logger.info(f"尝试重试... (剩余重试次数: {cls._config.max_retries})")
                time.sleep(cls._config.retry_delay)
                return cls.execute_request(
                    url=url, method=method, data=data, data_format=data_format,
                    headers=headers, params=params, timeout=timeout,
                    follow_redirects=follow_redirects, verify_ssl=verify_ssl,
                    auth=auth, cookies=cookies, proxies=proxies,
                    allow_retry=False  # 只重试一次
                )

            return {"success": False, "error": error_msg}

        except requests.RequestException as e:
            error_msg = f"请求异常: {str(e)}"
            logger.error(f"HTTP {method} {url} -> {error_msg}")
            return {"success": False, "error": error_msg}

    @classmethod
    def _prepare_request_body(cls, data: Any, data_format: str) -> Optional[Union[str, bytes]]:
        """根据数据格式准备请求体"""
        if data is None:
            return None

        data_format = data_format.lower()

        try:
            if data_format == "json":
                if isinstance(data, str):
                    # 验证JSON字符串有效性
                    json.loads(data)
                    return data
                return json.dumps(data)

            elif data_format == "xml":
                if isinstance(data, str):
                    # 验证XML字符串有效性
                    ET.fromstring(data)
                    return data
                return str(data)

            elif data_format == "form":
                if isinstance(data, dict):
                    return data
                elif isinstance(data, str):
                    return data
                return str(data)

            elif data_format == "multipart":
                if isinstance(data, dict):
                    return data
                return data

            elif data_format in ["text", "html"]:
                return str(data)

            else:
                # 默认尝试作为JSON处理
                if isinstance(data, str):
                    return data
                return json.dumps(data)

        except json.JSONDecodeError as e:
            logger.warning(f"JSON解析失败: {e}")
            return str(data)
        except ET.ParseError as e:
            logger.warning(f"XML解析失败: {e}")
            return str(data)

    @classmethod
    def _parse_response(cls, response: requests.Response) -> Dict[str, Any]:
        """解析HTTP响应内容"""
        result = {}

        content_type = response.headers.get("Content-Type", "").lower()

        # 尝试解析JSON
        if "application/json" in content_type:
            try:
                result["json"] = response.json()
                result["parsed_type"] = "json"
            except json.JSONDecodeError:
                pass

        # 尝试解析XML
        elif "application/xml" in content_type or "text/xml" in content_type:
            try:
                root = ET.fromstring(response.text)
                result["xml"] = cls._xml_to_dict(root)
                result["parsed_type"] = "xml"
            except ET.ParseError:
                pass

        # HTML内容分析
        elif "text/html" in content_type:
            result["parsed_type"] = "html"
            result.update(cls._parse_html(response.text))

        return result

    @classmethod
    def _xml_to_dict(cls, element: ET.Element) -> Dict[str, Any]:
        """将XML元素转换为字典"""
        result = {}

        for child in element:
            child_data = cls._xml_to_dict(child) if len(child) > 0 else child.text

            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_data)
            else:
                result[child.tag] = child_data

        # 添加属性
        if element.attrib:
            result["@attributes"] = element.attrib

        return result

    @classmethod
    def _parse_html(cls, content: str) -> Dict[str, Any]:
        """解析HTML内容"""
        soup = BeautifulSoup(content, 'html.parser')

        result = {
            "title": "",
            "forms": [],
            "links": [],
            "comments": [],
            "html_comments": [],
            "hidden_inputs": [],
            "scripts": [],
            "meta_tags": {},
            "ctf_hints": [],
            "flags_found": []
        }

        # 获取标题
        title_tag = soup.find('title')
        if title_tag:
            result["title"] = title_tag.get_text().strip()

        # 获取所有表单
        forms = soup.find_all('form')
        for form in forms:
            form_info = {
                "action": form.get('action'),
                "method": form.get('method', 'GET').upper(),
                "name": form.get('name'),
                "id": form.get('id'),
                "enctype": form.get('enctype'),
                "inputs": []
            }
            for input_tag in form.find_all('input'):
                input_info = {
                    "type": input_tag.get('type', 'text'),
                    "name": input_tag.get('name'),
                    "value": input_tag.get('value'),
                    "placeholder": input_tag.get('placeholder')
                }
                form_info["inputs"].append(input_info)

                if input_info["type"] == "hidden":
                    result["hidden_inputs"].append(input_info)

            # 收集textarea
            for textarea in form.find_all('textarea'):
                form_info["inputs"].append({
                    "type": "textarea",
                    "name": textarea.get('name'),
                    "value": textarea.get_text().strip()
                })

            # 收集select
            for select in form.find_all('select'):
                options = [{"value": opt.get('value'), "text": opt.get_text()}
                          for opt in select.find_all('option')]
                form_info["inputs"].append({
                    "type": "select",
                    "name": select.get('name'),
                    "options": options
                })

            result["forms"].append(form_info)

        # 获取所有链接
        for link in soup.find_all('a'):
            link_info = {
                "text": link.text.strip(),
                "href": link.get('href')
            }
            result["links"].append(link_info)

        # 查找HTML注释
        from bs4 import Comment
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            comment_text = comment.strip()
            result["comments"].append(comment_text)
            result["html_comments"].append(comment_text)

        # 查找脚本
        for script in soup.find_all('script'):
            script_info = {
                "type": script.get('type'),
                "src": script.get('src'),
                "content": script.string.strip() if script.string else ""
            }
            result["scripts"].append(script_info)

        # 查找meta标签
        meta_tags = soup.find_all('meta')
        for meta in meta_tags:
            name = meta.get('name') or meta.get('property')
            if name:
                result["meta_tags"][name] = meta.get('content', '')

        # CTF线索检测
        text_lower = content.lower()
        ctf_keywords = ['flag', 'ctf', 'hidden', 'secret', 'password', 'admin', 'login',
                       'decode', 'encode', 'base64', 'token', 'api_key', 'credential']

        for keyword in ctf_keywords:
            if keyword in text_lower:
                result["ctf_hints"].append({"pattern": keyword})

        # 直接检测flag格式
        flag_patterns = [
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

        for pattern in flag_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match not in result["flags_found"]:
                    result["flags_found"].append(match)

        # 在HTML注释中检测flag
        for comment in result["html_comments"]:
            for pattern in flag_patterns:
                matches = re.findall(pattern, comment, re.IGNORECASE)
                for match in matches:
                    if match not in result["flags_found"]:
                        result["flags_found"].append(match)

        # 在隐藏字段中检测flag
        for hidden in result["hidden_inputs"]:
            hidden_str = str(hidden)
            for pattern in flag_patterns:
                matches = re.findall(pattern, hidden_str, re.IGNORECASE)
                for match in matches:
                    if match not in result["flags_found"]:
                        result["flags_found"].append(match)

        return result

    @classmethod
    def fetch_page(cls, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        获取网页内容（兼容旧接口）

        注意：返回结果现在同时包含 'content' 和 'raw_content' 键
        """
        options = options or {}
        return cls.execute_request(
            url=target,
            method=options.get("method", "GET"),
            headers=options.get("headers"),
            timeout=options.get("timeout"),
            follow_redirects=options.get("follow_redirects", True)
        )

    @classmethod
    def analyze_content(cls, content: str, url: str) -> Dict[str, Any]:
        """分析网页内容，返回结构化信息"""
        result = cls._parse_html(content)
        result["url"] = url
        result["content"] = content
        return result

    # ==================== 便捷方法 ====================

    @classmethod
    def get(cls, url: str, params: Optional[Dict] = None, headers: Optional[Dict] = None,
            **kwargs) -> Dict[str, Any]:
        """发送GET请求"""
        return cls.execute_request(url, method="GET", params=params, headers=headers, **kwargs)

    @classmethod
    def post(cls, url: str, data: Any = None, data_format: str = "json",
             headers: Optional[Dict] = None, **kwargs) -> Dict[str, Any]:
        """发送POST请求"""
        return cls.execute_request(url, method="POST", data=data, data_format=data_format,
                                  headers=headers, **kwargs)

    @classmethod
    def put(cls, url: str, data: Any = None, data_format: str = "json",
            headers: Optional[Dict] = None, **kwargs) -> Dict[str, Any]:
        """发送PUT请求"""
        return cls.execute_request(url, method="PUT", data=data, data_format=data_format,
                                  headers=headers, **kwargs)

    @classmethod
    def delete(cls, url: str, headers: Optional[Dict] = None, **kwargs) -> Dict[str, Any]:
        """发送DELETE请求"""
        return cls.execute_request(url, method="DELETE", headers=headers, **kwargs)

    @classmethod
    def patch(cls, url: str, data: Any = None, data_format: str = "json",
              headers: Optional[Dict] = None, **kwargs) -> Dict[str, Any]:
        """发送PATCH请求"""
        return cls.execute_request(url, method="PATCH", data=data, data_format=data_format,
                                  headers=headers, **kwargs)

    @classmethod
    def head(cls, url: str, headers: Optional[Dict] = None, **kwargs) -> Dict[str, Any]:
        """发送HEAD请求"""
        return cls.execute_request(url, method="HEAD", headers=headers, **kwargs)

    @classmethod
    def options(cls, url: str, headers: Optional[Dict] = None, **kwargs) -> Dict[str, Any]:
        """发送OPTIONS请求"""
        return cls.execute_request(url, method="OPTIONS", headers=headers, **kwargs)

    # ==================== 特殊用途方法 ====================

    @classmethod
    def post_json(cls, url: str, json_data: Union[Dict, List, str],
                  headers: Optional[Dict] = None, **kwargs) -> Dict[str, Any]:
        """发送JSON格式的POST请求"""
        return cls.post(url, data=json_data, data_format="json", headers=headers, **kwargs)

    @classmethod
    def post_xml(cls, url: str, xml_data: str,
                 headers: Optional[Dict] = None, **kwargs) -> Dict[str, Any]:
        """发送XML格式的POST请求"""
        return cls.post(url, data=xml_data, data_format="xml", headers=headers, **kwargs)

    @classmethod
    def post_form(cls, url: str, form_data: Union[Dict, str],
                  headers: Optional[Dict] = None, **kwargs) -> Dict[str, Any]:
        """发送表单格式的POST请求"""
        return cls.post(url, data=form_data, data_format="form", headers=headers, **kwargs)

    @classmethod
    def upload_file(cls, url: str, files: Dict[str, tuple],
                    additional_data: Optional[Dict] = None,
                    headers: Optional[Dict] = None,
                    timeout: Optional[int] = None,
                    **kwargs) -> Dict[str, Any]:
        """
        上传文件（改进版 - 返回格式统一）

        Args:
            url: 目标URL
            files: 文件字典，格式为 {"field_name": ("filename", file_content, content_type)}
            additional_data: 额外的表单数据
            headers: 自定义请求头
            timeout: 超时时间
        """
        # 注意：使用multipart时不能预设Content-Type，requests会自动设置
        if headers and "Content-Type" in headers:
            del headers["Content-Type"]

        timeout = timeout or cls._config.timeout

        try:
            session = cls._get_session()
            start_time = time.time()

            logger.info(f"HTTP POST (upload) {url}")

            response = session.post(
                url=url,
                files=files,
                data=additional_data,
                headers=headers,
                timeout=timeout,
                **kwargs
            )

            elapsed_time = time.time() - start_time

            # 统一返回格式
            return {
                "success": True,
                "status_code": response.status_code,
                "reason": response.reason,
                "headers": dict(response.headers),
                "cookies": dict(response.cookies),
                "url": response.url,
                "elapsed_time": round(elapsed_time, 3),
                "content": response.text,
                "raw_content": response.text,  # 向后兼容
                "content_length": len(response.content)
            }

        except requests.exceptions.Timeout:
            return {"success": False, "error": f"请求超时 ({timeout}秒)"}
        except requests.exceptions.SSLError as e:
            return {"success": False, "error": f"SSL错误: {str(e)}"}
        except requests.exceptions.ConnectionError as e:
            return {"success": False, "error": f"连接错误: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ==================== 代理相关方法 ====================

    @classmethod
    def set_proxy(cls, http_proxy: Optional[str] = None, https_proxy: Optional[str] = None) -> None:
        """
        设置代理

        Args:
            http_proxy: HTTP代理地址，如 "http://127.0.0.1:8080"
            https_proxy: HTTPS代理地址，如 "http://127.0.0.1:8080"
        """
        proxies = {}
        if http_proxy:
            proxies["http"] = http_proxy
        if https_proxy:
            proxies["https"] = https_proxy

        cls._config.proxies = proxies if proxies else None
        cls._session = None  # 重置session

        if proxies:
            logger.info(f"代理已设置: {proxies}")
        else:
            logger.info("代理已清除")

    @classmethod
    def clear_proxy(cls) -> None:
        """清除代理设置"""
        cls.set_proxy()


# ==================== 命令行接口 ====================

def parse_http_command(command: str) -> Dict[str, Any]:
    """
    解析HTTP命令字符串

    支持的格式:
    - http get http://example.com
    - http post http://api.example.com json '{"key":"value"}'
    - http post http://example.com form 'username=admin&password=test'
    - http put http://api.example.com/1 xml '<data>test</data>'
    - http --method POST --data 'key=value' http://example.com
    - http -method POST -url http://example.com -data 'key=value'
    """
    import shlex

    result = {
        "method": "GET",
        "url": None,
        "data_format": None,
        "data": None
    }

    try:
        # 使用 shlex 来正确处理引号
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()

    if len(parts) < 2:
        return {"error": "命令格式错误"}

    # 跳过 "http" 前缀（如果存在）
    if parts[0].lower() == "http":
        parts = parts[1:]

    if len(parts) < 1:
        return {"error": "命令格式错误"}

    # 辅助函数：检查是否为参数标志
    def is_flag(part: str, name: str) -> bool:
        """检查是否为指定参数的标志（支持 -name 和 --name）"""
        return part == f"-{name}" or part == f"--{name}"

    # 检查是否使用标志格式 (-method/--method/-url/--url/-data/--data)
    if parts[0].startswith("-"):
        i = 0
        while i < len(parts):
            part = parts[i]

            if is_flag(part, "method") and i + 1 < len(parts):
                result["method"] = parts[i + 1].upper()
                i += 2
            elif is_flag(part, "url") and i + 1 < len(parts):
                result["url"] = parts[i + 1]
                i += 2
            elif is_flag(part, "data") and i + 1 < len(parts):
                result["data"] = parts[i + 1]
                result["data_format"] = "form"  # 默认使用 form 格式
                i += 2
            elif is_flag(part, "format") and i + 1 < len(parts):
                result["data_format"] = parts[i + 1].lower()
                i += 2
            elif is_flag(part, "timeout") and i + 1 < len(parts):
                # 额外参数，暂时忽略
                i += 2
            elif part.startswith("http://") or part.startswith("https://"):
                result["url"] = part
                i += 1
            else:
                i += 1
    else:
        # 简单格式: method url [format] [data]
        result["method"] = parts[0].upper()

        # 找到 URL (以 http:// 或 https:// 开头)
        url_idx = None
        for idx, part in enumerate(parts[1:], start=1):
            if part.startswith("http://") or part.startswith("https://"):
                url_idx = idx
                break

        if url_idx is None:
            # 如果没找到，假设第二个参数是 URL
            if len(parts) >= 2:
                result["url"] = parts[1]
        else:
            result["url"] = parts[url_idx]

            # 如果 URL 之前有 format，URL 之后有 data
            if url_idx == 3 and len(parts) >= 4:
                result["data_format"] = parts[2].lower()
                result["data"] = parts[3]

    if result["url"] is None:
        return {"error": "命令格式错误: 未找到URL"}

    return result


def execute_http_command(command: str) -> Dict[str, Any]:
    """执行HTTP命令"""
    parsed = parse_http_command(command)

    if "error" in parsed:
        return parsed

    return HTTPTool.execute_request(
        url=parsed["url"],
        method=parsed["method"],
        data=parsed["data"],
        data_format=parsed["data_format"] or "json"
    )
