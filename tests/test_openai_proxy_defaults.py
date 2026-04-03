import unittest
from unittest.mock import patch

import src.core.http_client as http_client_module
import src.core.openai.token_refresh as token_refresh_module
import src.core.register as register_module
from src.core.http_client import OpenAIHTTPClient
from src.core.openai.token_refresh import TokenRefreshManager
from src.core.register import RegistrationEngine
from src.services import EmailServiceType


class DummySettings:
    proxy_url = "http://proxy.example.test:8080"
    openai_client_id = "client-id"
    openai_auth_url = "https://auth.example.test"
    openai_token_url = "https://token.example.test"
    openai_redirect_uri = "https://callback.example.test"
    openai_scope = "openid email profile"
    email_code_timeout = 120


class FakeEmailService:
    service_type = EmailServiceType.TEMP_MAIL


class TestOpenAIProxyDefaults(unittest.TestCase):
    def test_openai_http_client_uses_settings_proxy_by_default(self):
        with patch.object(http_client_module, "get_settings", return_value=DummySettings()):
            client = OpenAIHTTPClient()

        self.assertEqual(client.proxy_url, DummySettings.proxy_url)
        self.assertEqual(
            client.proxies,
            {
                "http": DummySettings.proxy_url,
                "https": DummySettings.proxy_url,
            },
        )

    def test_token_refresh_manager_uses_settings_proxy_by_default(self):
        captured = {}

        def fake_session(*args, **kwargs):
            captured.update(kwargs)
            return object()

        with patch.object(token_refresh_module, "get_settings", return_value=DummySettings()):
            with patch.object(http_client_module, "get_settings", return_value=DummySettings()):
                with patch.object(token_refresh_module.cffi_requests, "Session", side_effect=fake_session):
                    manager = TokenRefreshManager()
                    manager._create_session()

        self.assertEqual(captured.get("proxy"), DummySettings.proxy_url)

    def test_registration_engine_uses_settings_proxy_by_default(self):
        with patch.object(register_module, "get_settings", return_value=DummySettings()):
            with patch.object(http_client_module, "get_settings", return_value=DummySettings()):
                engine = RegistrationEngine(email_service=FakeEmailService())

        self.assertEqual(engine.proxy_url, DummySettings.proxy_url)
        self.assertEqual(engine.http_client.proxy_url, DummySettings.proxy_url)
        self.assertEqual(engine.oauth_manager.proxy_url, DummySettings.proxy_url)


if __name__ == "__main__":
    unittest.main()
