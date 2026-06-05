"""Tests for FritzWebUI module."""

from unittest.mock import MagicMock, patch

from fritzconnection.lib.fritzwebui import (
    FritzWebUI,
    API_LOGIN,
    API_DATA,
    DEFAULT_TIMEOUT,
    _parse_challenge_from_login_xml,
    _parse_sid_from_login_response,
    _calculate_pbkdf2_response,
    _calculate_md5_response,
)


def _mock_fc(*, use_tls: bool = True) -> MagicMock:
    mock_fc = MagicMock()
    mock_fc.address = "https://192.168.178.1" if use_tls else "http://192.168.178.1"
    mock_fc.port = 49443 if use_tls else 49000
    mock_fc.soaper.user = "admin"
    mock_fc.soaper.password = "password"
    mock_fc.session = MagicMock()
    if use_tls:
        mock_fc.call_action.return_value = {"NewPort": 443}
    return mock_fc


def test_module_imports():
    assert API_LOGIN == "/login_sid.lua"
    assert API_DATA == "/data.lua"
    assert DEFAULT_TIMEOUT == 10


def test_fritzwebui_base_url():
    assert FritzWebUI(fc=_mock_fc())._base_url == "https://192.168.178.1:443"
    assert FritzWebUI(fc=_mock_fc(use_tls=False))._base_url == "http://192.168.178.1:80"


def test_parse_challenge_from_login_xml():
    xml = '<?xml version="1.0"?><SessionInfo><Challenge>12345abc</Challenge></SessionInfo>'
    assert _parse_challenge_from_login_xml(xml) == "12345abc"


def test_parse_challenge_invalid_xml():
    assert _parse_challenge_from_login_xml("not xml") is None


def test_parse_sid_from_xml():
    xml = '<?xml version="1.0"?><SessionInfo><SID>1234567890abcdef</SID></SessionInfo>'
    assert _parse_sid_from_login_response(xml) == "1234567890abcdef"


def test_parse_sid_from_html():
    html = '<html>sid: 1234567890abcdef</html>'
    assert _parse_sid_from_login_response(html) == "1234567890abcdef"


def test_parse_sid_invalid():
    xml = '<?xml version="1.0"?><SessionInfo><SID>0000000000000000</SID></SessionInfo>'
    assert _parse_sid_from_login_response(xml) is None


def test_calculate_md5_response():
    response = _calculate_md5_response("12345", "testpass")
    assert response.startswith("12345-")
    assert len(response.split("-", 1)[1]) == 32


def test_calculate_pbkdf2_response():
    challenge = "2$10000$abcd1234$10000$ef567890"
    response = _calculate_pbkdf2_response(challenge, "testpass")
    assert response is not None
    assert response.startswith("ef567890$")
    assert len(response.split("$", 1)[1]) == 64


def test_calculate_pbkdf2_invalid():
    assert _calculate_pbkdf2_response("invalid", "password") is None


def test_request_get_includes_sid_and_accept_header():
    fc = _mock_fc()
    fw = FritzWebUI(fc=fc)
    fw._sid = "sid123"
    fc.session.get.return_value = MagicMock(
        text='{"result":"ok"}',
        json=MagicMock(return_value={"result": "ok"}),
        raise_for_status=MagicMock(),
    )

    with patch.object(fw, "_ensure_sid", return_value="sid123"):
        result = fw._request(
            API_DATA,
            {"page": "shareWireguard"},
            method="GET",
        )

    expected_url = f"{fw._base_url}{API_DATA}"
    expected_headers = {"Accept": "application/json"}
    expected_params = {"page": "shareWireguard", "sid": "sid123"}
    fc.session.get.assert_called_once_with(
        expected_url,
        params=expected_params,
        headers=expected_headers,
        timeout=DEFAULT_TIMEOUT,
    )
    assert result == {"result": "ok"}


def test_request_post_includes_sid_and_accept_header():
    fc = _mock_fc()
    fw = FritzWebUI(fc=fc)
    fw._sid = "sid123"
    fc.session.post.return_value = MagicMock(
        text='{"result":"ok"}',
        json=MagicMock(return_value={"result": "ok"}),
        raise_for_status=MagicMock(),
    )

    with patch.object(fw, "_ensure_sid", return_value="sid123"):
        result = fw._request(
            API_DATA,
            {"page": "shareWireguard"},
            method="POST",
        )

    expected_url = f"{fw._base_url}{API_DATA}"
    expected_headers = {"Accept": "application/json"}
    expected_data = {"page": "shareWireguard", "sid": "sid123"}
    fc.session.post.assert_called_once_with(
        expected_url,
        data=expected_data,
        headers=expected_headers,
        timeout=DEFAULT_TIMEOUT,
    )
    assert result == {"result": "ok"}


def test_request_put_includes_authorization_content_type_and_json_body():
    fc = _mock_fc()
    fw = FritzWebUI(fc=fc)
    fw._sid = "sid123"
    fc.session.put.return_value = MagicMock(
        text='{"result":"ok"}',
        json=MagicMock(return_value={"result": "ok"}),
        raise_for_status=MagicMock(),
    )

    endpoint = "/api/v0/generic/vpn/connection/uid-office"
    json_body = {"activated": 1}

    with patch.object(fw, "_ensure_sid", return_value="sid123"):
        result = fw._request(
            endpoint,
            method="PUT",
            json_body=json_body,
        )

    expected_url = f"{fw._base_url}{endpoint}"
    expected_headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": "AVM-SID sid123",
        "Origin": fc.address,
        "Referer": f"{fc.address}/",
    }
    fc.session.put.assert_called_once_with(
        expected_url,
        headers=expected_headers,
        json=json_body,
        timeout=DEFAULT_TIMEOUT,
    )
    assert result == {"result": "ok"}
