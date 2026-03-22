"""
Mail.tm 邮箱服务实现
基于 Mail.tm API (https://api.mail.tm)
"""

import re
import time
import json
import logging
import random
import string
from typing import Optional, Dict, Any, List

from .base import BaseEmailService, EmailServiceError, EmailServiceType
from ..core.http_client import HTTPClient, RequestConfig
from ..config.constants import OTP_CODE_PATTERN


logger = logging.getLogger(__name__)


class MailTmService(BaseEmailService):
    """
    Mail.tm 邮箱服务
    官方 API 文档: https://api.mail.tm
    """

    def __init__(self, config: Dict[str, Any] = None, name: str = None):
        """
        初始化 Mail.tm 服务

        Args:
            config: 配置字典，支持以下键:
                - base_url: API 基础地址 (默认: https://api.mail.tm)
                - domain: 邮箱域名 (可选，不指定则自动获取)
                - password: 邮箱密码 (可选，默认自动生成)
                - timeout: 请求超时时间 (默认: 30)
                - max_retries: 最大重试次数 (默认: 3)
                - proxy_url: 代理 URL
            name: 服务名称
        """
        super().__init__(EmailServiceType.MAIL_TM, name)

        default_config = {
            "base_url": "https://api.mail.tm",
            "domain": None,
            "password": None,
            "timeout": 30,
            "max_retries": 3,
            "proxy_url": None,
        }

        self.config = {**default_config, **(config or {})}

        # 创建 HTTP 客户端
        http_config = RequestConfig(
            timeout=self.config["timeout"],
            max_retries=self.config["max_retries"],
        )
        self.http_client = HTTPClient(
            proxy_url=self.config.get("proxy_url"),
            config=http_config
        )

        # 状态变量
        self._email_cache: Dict[str, Dict[str, Any]] = {}
        self._available_domains: List[str] = []

    def _get_headers(self, token: str = None) -> Dict[str, str]:
        """获取请求头"""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _make_request(
        self,
        method: str,
        path: str,
        token: str = None,
        **kwargs
    ) -> Any:
        """
        发送请求并返回 JSON 数据

        Args:
            method: HTTP 方法
            path: 请求路径
            token: 认证 token (可选)
            **kwargs: 传递给 http_client.request 的额外参数

        Returns:
            响应 JSON 数据

        Raises:
            EmailServiceError: 请求失败
        """
        base_url = self.config["base_url"].rstrip("/")
        url = f"{base_url}{path}"

        kwargs.setdefault("headers", {})
        for k, v in self._get_headers(token).items():
            kwargs["headers"].setdefault(k, v)

        try:
            response = self.http_client.request(method, url, **kwargs)

            if response.status_code >= 400:
                error_msg = f"请求失败: {response.status_code}"
                try:
                    error_data = response.json()
                    # Mail.tm 返回 "hydra:description" 字段
                    if "hydra:description" in error_data:
                        error_msg = f"{error_msg} - {error_data['hydra:description']}"
                    elif "message" in error_data:
                        error_msg = f"{error_msg} - {error_data['message']}"
                    else:
                        error_msg = f"{error_msg} - {error_data}"
                except Exception:
                    error_msg = f"{error_msg} - {response.text[:200]}"
                raise EmailServiceError(error_msg)

            try:
                return response.json()
            except json.JSONDecodeError:
                return {"raw_response": response.text}

        except Exception as e:
            if isinstance(e, EmailServiceError):
                raise
            raise EmailServiceError(f"请求失败: {method} {path} - {e}")

    def _get_available_domains(self) -> List[str]:
        """获取可用域名列表"""
        if self._available_domains:
            return self._available_domains

        try:
            response = self._make_request("GET", "/domains")
            # API 可能直接返回列表，也可能返回 {"hydra:member": [...]} 格式
            if isinstance(response, list):
                domains = response
            else:
                domains = response.get("hydra:member", [])
            self._available_domains = [d["domain"] for d in domains if d.get("isActive")]
            return self._available_domains
        except Exception as e:
            logger.warning(f"获取域名列表失败: {e}")
            return []

    def create_email(self, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        创建新的临时邮箱

        Returns:
            包含邮箱信息的字典:
            - email: 邮箱地址
            - service_id: 账户 ID
            - account_id: 账户 ID
            - token: JWT token
            - password: 邮箱密码
        """
        # 生成随机邮箱名
        letters = ''.join(random.choices(string.ascii_lowercase, k=6))
        digits = ''.join(random.choices(string.digits, k=3))
        username = letters + digits

        # 获取域名
        domain = self.config.get("domain")
        if not domain:
            domains = self._get_available_domains()
            if not domains:
                raise EmailServiceError("没有可用的邮箱域名")
            domain = random.choice(domains)

        email_address = f"{username}@{domain}"

        # 生成密码
        password = self.config.get("password") or self._generate_password()

        try:
            # 1. 创建账户
            account = self._make_request(
                "POST",
                "/accounts",
                json={"address": email_address, "password": password}
            )

            account_id = account.get("id")
            if not account_id:
                raise EmailServiceError(f"创建账户失败: {account}")

            # 2. 获取 JWT token
            token_response = self._make_request(
                "POST",
                "/token",
                json={"address": email_address, "password": password}
            )

            token = token_response.get("token")
            if not token:
                raise EmailServiceError(f"获取 token 失败: {token_response}")

            email_info = {
                "email": email_address,
                "service_id": account_id,
                "account_id": account_id,
                "token": token,
                "password": password,
                "created_at": time.time(),
            }

            self._email_cache[email_address] = email_info

            logger.info(f"成功创建 Mail.tm 邮箱: {email_address}")
            self.update_status(True)
            return email_info

        except Exception as e:
            self.update_status(False, e)
            if isinstance(e, EmailServiceError):
                raise
            raise EmailServiceError(f"创建邮箱失败: {e}")

    def _generate_password(self, length: int = 12) -> str:
        """生成随机密码"""
        chars = string.ascii_letters + string.digits + "!@#$%"
        return ''.join(random.choices(chars, k=length))

    def get_verification_code(
        self,
        email: str,
        email_id: str = None,
        timeout: int = 120,
        pattern: str = OTP_CODE_PATTERN,
        otp_sent_at: Optional[float] = None,
    ) -> Optional[str]:
        """
        从 Mail.tm 邮箱获取验证码

        Args:
            email: 邮箱地址
            email_id: 未使用，保留接口兼容
            timeout: 超时时间（秒）
            pattern: 验证码正则

        Returns:
            验证码字符串，超时返回 None
        """
        # 从缓存获取 token
        cached = self._email_cache.get(email, {})
        token = cached.get("token")

        if not token:
            logger.warning(f"未找到邮箱 {email} 的 token")
            return None

        logger.info(f"正在从 Mail.tm 邮箱 {email} 获取验证码...")

        start_time = time.time()
        seen_ids: set = set()

        while time.time() - start_time < timeout:
            try:
                response = self._make_request(
                    "GET",
                    "/messages",
                    token=token
                )

                if isinstance(response, list):
                    messages = response
                else:
                    messages = response.get("hydra:member", [])
                if not isinstance(messages, list):
                    time.sleep(3)
                    continue

                for msg in messages:
                    msg_id = msg.get("id")
                    if not msg_id or msg_id in seen_ids:
                        continue

                    seen_ids.add(msg_id)

                    list_sender = ""
                    if isinstance(msg.get("from"), dict):
                        list_sender = str(msg.get("from", {}).get("address", "")).lower()
                    list_subject = str(msg.get("subject", "")).lower()
                    list_intro = str(msg.get("intro", "") or "")
                    list_content = f"{list_sender}\n{list_subject}\n{list_intro}".lower()

                    if ("openai" in list_sender or "openai" in list_content):
                        logger.info(
                            f"Mail.tm 收到疑似 OpenAI 邮件: sender={list_sender or 'unknown'}, subject={list_subject or 'unknown'}"
                        )
                        intro_match = re.search(pattern, list_content)
                        if intro_match:
                            code = intro_match.group(1)
                            logger.info(f"从 Mail.tm 邮件预览中找到验证码: {code}")
                            self.update_status(True)
                            return code

                    # 获取邮件详情
                    try:
                        detail = self._make_request(
                            "GET",
                            f"/messages/{msg_id}",
                            token=token
                        )
                    except Exception:
                        continue

                    sender = str(detail.get("from", {})).lower()
                    if isinstance(detail.get("from"), dict):
                        sender = detail.get("from", {}).get("address", "").lower()

                    subject = str(detail.get("subject", "")).lower()
                    intro = str(detail.get("intro", "") or "")
                    text = str(detail.get("text", "") or "")
                    html = str(detail.get("html", []) or "")
                    if isinstance(html, list):
                        html = " ".join(html)

                    content = f"{sender}\n{subject}\n{intro}\n{text}\n{html}".lower()

                    # 只处理 OpenAI 邮件
                    if "openai" not in sender and "openai" not in content:
                        continue

                    # 提取验证码
                    match = re.search(pattern, content)
                    if match:
                        code = match.group(1)
                        logger.info(f"从 Mail.tm 邮箱 {email} 找到验证码: {code}")
                        self.update_status(True)
                        return code

            except Exception as e:
                logger.debug(f"检查邮件时出错: {e}")

            time.sleep(3)

        logger.warning(f"等待 Mail.tm 验证码超时: {email}")
        return None

    def list_emails(self, **kwargs) -> List[Dict[str, Any]]:
        """列出邮箱（返回缓存）"""
        return list(self._email_cache.values())

    def delete_email(self, email_id: str) -> bool:
        """删除邮箱（从缓存移除）"""
        emails_to_delete = []
        for email, info in self._email_cache.items():
            if info.get("account_id") == email_id or email == email_id:
                emails_to_delete.append(email)

        for email in emails_to_delete:
            del self._email_cache[email]
            logger.info(f"从缓存移除邮箱: {email}")

        return len(emails_to_delete) > 0

    def check_health(self) -> bool:
        """检查服务健康状态"""
        try:
            domains = self._get_available_domains()
            if domains:
                self.update_status(True)
                return True
            return False
        except Exception as e:
            logger.warning(f"Mail.tm 健康检查失败: {e}")
            self.update_status(False, e)
            return False
