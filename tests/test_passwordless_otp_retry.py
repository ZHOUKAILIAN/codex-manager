import unittest
from unittest.mock import Mock, patch

import src.core.register as register_module
from src.core.register import RegistrationEngine
from src.config.constants import OPENAI_API_ENDPOINTS
from src.services import EmailServiceType


class DummySettings:
    openai_client_id = "client-id"
    openai_auth_url = "https://auth.example.test"
    openai_token_url = "https://token.example.test"
    openai_redirect_uri = "https://callback.example.test"
    openai_scope = "openid profile email"
    email_code_timeout = 120


class FakeEmailService:
    service_type = EmailServiceType.TEMP_MAIL


class FakeCookies(dict):
    def get(self, name, default=None):
        return super().get(name, default)


class CapturingTempMailService(FakeEmailService):
    def __init__(self):
        self.calls = []

    def get_verification_code(self, **kwargs):
        self.calls.append(kwargs)
        return "654321"


class CapturingOutlookService(FakeEmailService):
    service_type = EmailServiceType.OUTLOOK

    def __init__(self):
        self.calls = []

    def get_verification_code(self, **kwargs):
        self.calls.append(kwargs)
        return "654321"


class FakeResponse:
    def __init__(self, status_code=200, json_payload=None, text=""):
        self.status_code = status_code
        self._json_payload = json_payload if json_payload is not None else {}
        self.text = text

    def json(self):
        return self._json_payload


def build_auth_cookie(payload):
    import base64
    import json

    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii").rstrip("=")
    return f"{encoded}.signature"


class FakeSession:
    def __init__(self, responses, get_responses=None, cookies=None):
        self._responses = list(responses)
        self._get_responses = get_responses or {}
        self.post_calls = []
        self.get_calls = []
        self.cookies = FakeCookies(cookies or {})

    def post(self, url, headers=None, data=None, timeout=None):
        self.post_calls.append(
            {
                "url": url,
                "headers": headers or {},
                "data": data,
                "timeout": timeout,
            }
        )
        if not self._responses:
            raise AssertionError(f"unexpected POST {url}")
        return self._responses.pop(0)

    def get(self, url, headers=None, timeout=None):
        self.get_calls.append({"url": url, "headers": headers or {}, "timeout": timeout})
        response = self._get_responses.get(url)
        if response is None:
            return FakeResponse(status_code=200)
        if callable(response):
            return response(url, headers, timeout)
        return response


class FakeHTTPClient:
    def __init__(self, session):
        self.session = session
        self.close_calls = 0

    def close(self):
        self.close_calls += 1


def build_engine(session, email_service=None, mock_workspace_id=True):
    with patch.object(register_module, "get_settings", return_value=DummySettings()):
        engine = RegistrationEngine(email_service=email_service or FakeEmailService())
    engine.email = "tester@example.com"
    engine.http_client = FakeHTTPClient(session)
    engine.session = session
    engine._start_oauth = Mock(return_value=True)
    engine._get_device_id = Mock(return_value="did-1")
    engine._check_sentinel = Mock(return_value="sen-token")
    if mock_workspace_id:
        engine._get_workspace_id = Mock(return_value="ws-1")
    return engine


class TestPasswordlessOtpRetry(unittest.TestCase):
    def test_get_workspace_id_falls_back_to_chatgpt_session(self):
        session = FakeSession(
            [],
            get_responses={
                "https://chatgpt.com/api/auth/session": FakeResponse(
                    200,
                    {"accessToken": "access-123"},
                ),
                "https://chatgpt.com/backend-api/me": FakeResponse(
                    200,
                    {"orgs": {"data": [{"id": "ws-session"}]}},
                ),
            },
            cookies={
                "oai-client-auth-session": build_auth_cookie({"workspaces": []}),
                "__Secure-next-auth.session-token": "session-token-123",
            },
        )
        engine = build_engine(session, mock_workspace_id=False)

        workspace_id = engine._get_workspace_id()

        self.assertEqual(workspace_id, "ws-session")
        self.assertEqual(
            [call["url"] for call in session.get_calls],
            [
                "https://chatgpt.com/api/auth/session",
                "https://chatgpt.com/backend-api/me",
            ],
        )

    def test_password_login_flow_returns_workspace_before_secondary_otp(self):
        session = FakeSession(
            [
                FakeResponse(
                    200,
                    {
                        "page": {"type": "login_password"},
                        "continue_url": "https://auth.openai.com/log-in/password",
                    },
                ),
                FakeResponse(
                    200,
                    {"continue_url": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"},
                ),
            ],
            get_responses={
                "https://auth.openai.com/log-in/password": FakeResponse(200, {}),
                "https://auth.openai.com/sign-in-with-chatgpt/codex/consent": FakeResponse(200, {}),
                "https://chatgpt.com/api/auth/session": FakeResponse(
                    200,
                    {"accessToken": "access-123"},
                ),
                "https://chatgpt.com/backend-api/me": FakeResponse(
                    200,
                    {"orgs": {"data": [{"id": "ws-password"}]}},
                ),
            },
            cookies={
                "oai-client-auth-session": build_auth_cookie({"workspaces": []}),
                "__Secure-next-auth.session-token": "session-token-123",
            },
        )
        engine = build_engine(session, mock_workspace_id=False)
        engine.password = "SecretPass123"
        engine._get_verification_code = Mock(side_effect=AssertionError("secondary otp should not be needed"))

        workspace_id = engine._password_login_flow()

        self.assertEqual(workspace_id, "ws-password")
        self.assertEqual(
            [call["url"] for call in session.post_calls],
            [
                OPENAI_API_ENDPOINTS["signup"],
                "https://auth.openai.com/api/accounts/password/verify",
            ],
        )

    def test_run_prefers_password_login_before_passwordless(self):
        session = FakeSession([])
        engine = build_engine(session)
        engine._check_ip_location = Mock(return_value=(True, "US"))
        engine._create_email = Mock(side_effect=lambda: setattr(engine, "email", "tester@example.com") or True)
        engine._init_session = Mock(return_value=True)
        engine._start_oauth = Mock(return_value=True)
        engine._get_device_id = Mock(return_value="did-1")
        engine._check_sentinel = Mock(return_value="sen-token")
        engine._submit_signup_form = Mock(return_value=register_module.SignupFormResult(success=True, is_existing_account=False))
        engine._register_password = Mock(return_value=(True, "SecretPass123"))
        engine._send_verification_code = Mock(return_value=True)
        engine._get_verification_code = Mock(return_value="654321")
        engine._validate_verification_code = Mock(return_value=True)
        engine._create_user_account = Mock(return_value=True)
        engine._get_workspace_id = Mock(return_value=None)
        engine._password_login_flow = Mock(return_value="ws-password")
        engine._passwordless_login_flow = Mock(return_value="ws-passwordless")
        engine._select_workspace = Mock(return_value="https://callback.example.test/continue")
        engine._follow_redirects = Mock(return_value="https://callback.example.test/auth?code=abc&state=xyz")
        engine._handle_oauth_callback = Mock(
            return_value={
                "account_id": "acct-1",
                "access_token": "access-1",
                "refresh_token": "refresh-1",
                "id_token": "id-1",
            }
        )
        engine.close = Mock()

        result = engine.run()

        self.assertTrue(result.success)
        self.assertEqual(result.workspace_id, "ws-password")
        engine._password_login_flow.assert_called_once()
        engine._passwordless_login_flow.assert_not_called()

    def test_run_attempts_password_login_when_register_password_fails(self):
        session = FakeSession([])
        engine = build_engine(session)
        engine._check_ip_location = Mock(return_value=(True, "US"))
        engine._create_email = Mock(side_effect=lambda: setattr(engine, "email", "tester@example.com") or True)
        engine._init_session = Mock(return_value=True)
        engine._start_oauth = Mock(return_value=True)
        engine._get_device_id = Mock(return_value="did-1")
        engine._check_sentinel = Mock(return_value="sen-token")
        engine._submit_signup_form = Mock(return_value=register_module.SignupFormResult(success=True, is_existing_account=False))

        def fake_register_password():
            engine.password = "RecoveredPass123"
            return False, None

        engine._register_password = Mock(side_effect=fake_register_password)
        engine._password_login_flow = Mock(return_value="ws-password")
        engine._passwordless_login_flow = Mock(return_value="ws-passwordless")
        engine._select_workspace = Mock(return_value="https://callback.example.test/continue")
        engine._follow_redirects = Mock(return_value="https://callback.example.test/auth?code=abc&state=xyz")
        engine._handle_oauth_callback = Mock(
            return_value={
                "account_id": "acct-1",
                "access_token": "access-1",
                "refresh_token": "refresh-1",
                "id_token": "id-1",
            }
        )
        engine.close = Mock()

        result = engine.run()

        self.assertTrue(result.success)
        self.assertEqual(result.workspace_id, "ws-password")
        engine._password_login_flow.assert_called_once()
        engine._passwordless_login_flow.assert_not_called()

    def test_run_attempts_passwordless_when_register_password_and_password_login_fail(self):
        session = FakeSession([])
        engine = build_engine(session)
        engine._check_ip_location = Mock(return_value=(True, "US"))
        engine._create_email = Mock(side_effect=lambda: setattr(engine, "email", "tester@example.com") or True)
        engine._init_session = Mock(return_value=True)
        engine._start_oauth = Mock(return_value=True)
        engine._get_device_id = Mock(return_value="did-1")
        engine._check_sentinel = Mock(return_value="sen-token")
        engine._submit_signup_form = Mock(return_value=register_module.SignupFormResult(success=True, is_existing_account=False))

        def fake_register_password():
            engine.password = "RecoveredPass123"
            return False, None

        engine._register_password = Mock(side_effect=fake_register_password)
        engine._password_login_flow = Mock(return_value=None)
        engine._passwordless_login_flow = Mock(return_value="ws-passwordless")
        engine._select_workspace = Mock(return_value="https://callback.example.test/continue")
        engine._follow_redirects = Mock(return_value="https://callback.example.test/auth?code=abc&state=xyz")
        engine._handle_oauth_callback = Mock(
            return_value={
                "account_id": "acct-1",
                "access_token": "access-1",
                "refresh_token": "refresh-1",
                "id_token": "id-1",
            }
        )
        engine.close = Mock()

        result = engine.run()

        self.assertTrue(result.success)
        self.assertEqual(result.workspace_id, "ws-passwordless")
        engine._password_login_flow.assert_called_once()
        engine._passwordless_login_flow.assert_called_once()

    def test_run_returns_phone_required_error_when_passwordless_hits_add_phone(self):
        session = FakeSession([])
        engine = build_engine(session)
        engine._check_ip_location = Mock(return_value=(True, "US"))
        engine._create_email = Mock(side_effect=lambda: setattr(engine, "email", "tester@example.com") or True)
        engine._init_session = Mock(return_value=True)
        engine._start_oauth = Mock(return_value=True)
        engine._get_device_id = Mock(return_value="did-1")
        engine._check_sentinel = Mock(return_value="sen-token")
        engine._submit_signup_form = Mock(return_value=register_module.SignupFormResult(success=True, is_existing_account=False))

        def fake_register_password():
            engine.password = "RecoveredPass123"
            return False, None

        def fake_passwordless():
            engine._phone_required_after_email_otp = True
            return None

        engine._register_password = Mock(side_effect=fake_register_password)
        engine._password_login_flow = Mock(return_value=None)
        engine._passwordless_login_flow = Mock(side_effect=fake_passwordless)
        engine.close = Mock()

        result = engine.run()

        self.assertFalse(result.success)
        self.assertEqual(result.error_message, "phone_required_after_email_otp")
        engine._password_login_flow.assert_called_once()
        engine._passwordless_login_flow.assert_called_once()

    def test_passwordless_uses_extended_timeout_for_temp_mail(self):
        session = FakeSession(
            [
                FakeResponse(200, {"page": {"type": "login_password"}}),
                FakeResponse(200, {}),
                FakeResponse(200, {"continue_url": ""}),
            ]
        )
        email_service = CapturingTempMailService()
        engine = build_engine(session, email_service=email_service)

        workspace_id = engine._passwordless_login_flow()

        self.assertEqual(workspace_id, "ws-1")
        self.assertEqual(len(email_service.calls), 1)
        self.assertEqual(email_service.calls[0]["timeout"], 300)

    def test_password_login_uses_extended_timeout_for_outlook_secondary_code(self):
        session = FakeSession(
            [
                FakeResponse(
                    200,
                    {
                        "page": {"type": "login_password"},
                        "continue_url": "https://auth.openai.com/log-in/password",
                    },
                ),
                FakeResponse(200, {}),
                FakeResponse(200, {"continue_url": ""}),
            ],
            get_responses={
                "https://auth.openai.com/log-in/password": FakeResponse(200, {}),
            },
        )
        email_service = CapturingOutlookService()
        engine = build_engine(session, email_service=email_service, mock_workspace_id=False)
        engine.password = "SecretPass123"
        engine._get_workspace_id = Mock(side_effect=[None, "ws-after-otp"])

        workspace_id = engine._password_login_flow()

        self.assertEqual(workspace_id, "ws-after-otp")
        self.assertEqual(len(email_service.calls), 1)
        self.assertEqual(email_service.calls[0]["timeout"], 300)

    def test_retries_when_secondary_code_is_missing(self):
        session = FakeSession(
            [
                FakeResponse(200, {"page": {"type": "login_password"}}),
                FakeResponse(200, {}),
                FakeResponse(200, {}),
                FakeResponse(200, {"continue_url": ""}),
            ]
        )
        engine = build_engine(session)
        engine._get_verification_code = Mock(side_effect=[None, "654321"])

        workspace_id = engine._passwordless_login_flow()

        self.assertEqual(workspace_id, "ws-1")
        self.assertEqual(engine._get_verification_code.call_count, 2)
        otp_posts = [call for call in session.post_calls if call["url"] == OPENAI_API_ENDPOINTS["passwordless_send_otp"]]
        self.assertEqual(len(otp_posts), 2)

    def test_retries_when_secondary_code_is_invalid(self):
        session = FakeSession(
            [
                FakeResponse(200, {"page": {"type": "login_password"}}),
                FakeResponse(200, {}),
                FakeResponse(
                    401,
                    {
                        "error": {
                            "message": "Wrong code. Please check it and try again.",
                            "code": "wrong_email_otp_code",
                        }
                    },
                    text='{"error":{"code":"wrong_email_otp_code"}}',
                ),
                FakeResponse(200, {}),
                FakeResponse(200, {"continue_url": ""}),
            ]
        )
        engine = build_engine(session)
        engine._get_verification_code = Mock(side_effect=["111111", "222222"])

        workspace_id = engine._passwordless_login_flow()

        self.assertEqual(workspace_id, "ws-1")
        self.assertEqual(engine._get_verification_code.call_count, 2)
        otp_posts = [call for call in session.post_calls if call["url"] == OPENAI_API_ENDPOINTS["passwordless_send_otp"]]
        self.assertEqual(len(otp_posts), 2)
        validate_posts = [call for call in session.post_calls if call["url"] == OPENAI_API_ENDPOINTS["validate_otp"]]
        self.assertEqual(len(validate_posts), 2)


if __name__ == "__main__":
    unittest.main()
