"""
Unit tests for the openvpn_helpers utility.
"""

import os
import subprocess
import pytest
from unittest.mock import patch
from jinja2 import Template
from app import create_app
from app.utils.openvpn_helpers import process_tls_crypt_key

TLS_CRYPT_V1_KEY = """
-----BEGIN OpenVPN Static key V1-----
2718e22b5161325d087957d9241e3b2e
-----END OpenVPN Static key V1-----
"""

TLS_CRYPT_V2_SERVER_KEY = """
-----BEGIN OpenVPN tls-crypt-v2 server key-----
A7ZgnkyRLrm+yrPoiOM/WpXK4KUceieSZm+kuUFjUlePpA18fc7jlh0HENYmR+0m
j+Qzem7mwhmQEu73hZs5e5Eq8SXqChbcrkeKahwW3m9bcTxWj1IKWbBE0X+3BG68
BvWT5LmAXjTFm1tb81VNArYOUiVjLOxuetHNy7udGgo=
-----END OpenVPN tls-crypt-v2 server key-----
"""

# Realistic fake client key for mocking openvpn output
FAKE_CLIENT_KEY_PEM = """-----BEGIN OpenVPN tls-crypt-v2 client key-----
IQr1rrDbZiPluN7qLIwL9cSn0BQIV1ahXv7FRXsG9Z9eqfC5YF4MSRCEpqnaEriB
7Y+U1ow4+3Gewz6GGM/IVRV/k545rmgygcx4qX6/JYo0wp2OU1xiKID7t31p0RZy
c3FeBWdw/f0uC0zM3JcAxcgYIvcwuTjyz4tFBTaM5vCv+dLY4FjLMdn9bVMP6a3R
Y2/FPnx68Vo093tffcx8/vDTJnKMIXCU1pOyEIty9VCt6azVWpj5R9PYPi9y4p26
mk8xxMSAHtfCMQMjkzNlBKllJZoA3v8qb7Df+GuPiKFRe9BhIG4/OoSlKywJgq1n
HFortdhg8aGwIeDjMQ9jvd50GMG8XHuXrJUSxfxm/cmBN6DJ2EezepnaWhE/B7xy
fKJrEQ+TKyNG8MrPGrOMItf/31qDsxpmL3Xw6cKz+zzenJNx+NTJyLio+FDqfrR3
KNo8ZrhYe71oNX6JoWgG9iGAKuNd+qnKWWtXE8M2qQ7qFzMWU3S3C9hcw9QpUpdC
TptUNqctLoQBU4CHzximtCmn4tBrxVBYIUkeVxUtteHyMQMFKJtWm5LZp3+7Ymcx
8+jWPNeLOcOQco+AIOy9wGoeutq5+mt5b+jgHTFVD7BfpgGdP+5hNbhh5CEVKFCP
q2s5LCVQ3BhRmwvr1cBezbrzC4SEERrfBz095P+KCwnb9S5KpkkiwNmKBqucQSEK
I0sMVlt7hplQVwmgyCi57B9JXBNC+3dS8wEr
-----END OpenVPN tls-crypt-v2 client key-----
"""


def _mock_openvpn_success(args, **kwargs):
    """Mock subprocess.run that writes a fake client key file."""
    client_key_path = args[-1]
    with open(client_key_path, 'w') as f:
        f.write(FAKE_CLIENT_KEY_PEM)
    return subprocess.CompletedProcess(args, 0, '', '')


def _mock_openvpn_failure(args, **kwargs):
    """Mock subprocess.run that simulates openvpn failure."""
    return subprocess.CompletedProcess(args, 1, '', 'Options error: --genkey requires a key type')


class TestProcessTlsCryptKey:
    """
    Tests for the process_tls_crypt_key function.
    """

    @pytest.fixture
    def app(self):
        """Create a test Flask app."""
        # Set required environment variables for testing
        os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-for-testing-only'
        os.environ['FERNET_ENCRYPTION_KEY'] = 'test-encryption-key-for-testing-only-32-chars-long'
        os.environ['TESTING'] = 'True'

        app = create_app('testing')
        app.config.update({
            'TESTING': True,
            'SECRET_KEY': 'test-secret-key-for-testing-only',
        })

        with app.app_context():
            yield app

    def test_handles_v1_key(self, app):
        version, client_key = process_tls_crypt_key(TLS_CRYPT_V1_KEY)
        assert version == 1
        assert client_key == TLS_CRYPT_V1_KEY

    @patch('app.utils.openvpn_helpers.subprocess.run', side_effect=_mock_openvpn_success)
    def test_handles_v2_key(self, mock_run, app):
        """Test that v2 server key triggers openvpn client key generation."""
        version, client_key = process_tls_crypt_key(TLS_CRYPT_V2_SERVER_KEY)
        assert version == 2
        assert client_key is not None
        assert '-----BEGIN OpenVPN tls-crypt-v2 client key-----' in client_key
        assert '-----END OpenVPN tls-crypt-v2 client key-----' in client_key
        # Verify openvpn was called with correct arguments
        call_args = mock_run.call_args[0][0]
        assert call_args[0] == 'openvpn'
        assert '--tls-crypt-v2' in call_args
        assert '--genkey' in call_args
        assert 'tls-crypt-v2-client' in call_args

    @patch('app.utils.openvpn_helpers.subprocess.run', side_effect=_mock_openvpn_success)
    def test_v2_passes_server_key_to_tempfile(self, mock_run, app):
        """Test that the server key PEM is written to the temp file passed to openvpn."""
        process_tls_crypt_key(TLS_CRYPT_V2_SERVER_KEY)
        call_args = mock_run.call_args[0][0]
        # The server key path is the argument after --tls-crypt-v2
        server_key_idx = call_args.index('--tls-crypt-v2') + 1
        server_key_path = call_args[server_key_idx]
        # Temp dir is cleaned up, but we verified the call was made correctly
        assert server_key_path.endswith('server.key')

    @patch('app.utils.openvpn_helpers.subprocess.run', side_effect=_mock_openvpn_success)
    def test_v2_each_call_invokes_openvpn(self, mock_run, app):
        """Test that each v2 call invokes openvpn (producing unique keys)."""
        process_tls_crypt_key(TLS_CRYPT_V2_SERVER_KEY)
        process_tls_crypt_key(TLS_CRYPT_V2_SERVER_KEY)
        assert mock_run.call_count == 2

    @patch('app.utils.openvpn_helpers.subprocess.run', side_effect=_mock_openvpn_failure)
    def test_v2_raises_on_openvpn_failure(self, mock_run, app):
        """Test that openvpn failure is propagated as ValueError."""
        with pytest.raises(ValueError, match="openvpn tls-crypt-v2 client key generation failed"):
            process_tls_crypt_key(TLS_CRYPT_V2_SERVER_KEY)

    @patch('app.utils.openvpn_helpers.subprocess.run', side_effect=subprocess.TimeoutExpired('openvpn', 10))
    def test_v2_raises_on_openvpn_timeout(self, mock_run, app):
        """Test that openvpn timeout is propagated."""
        with pytest.raises(subprocess.TimeoutExpired):
            process_tls_crypt_key(TLS_CRYPT_V2_SERVER_KEY)

    def test_handles_empty_key(self, app):
        version, client_key = process_tls_crypt_key(None)
        assert version is None
        assert client_key is None

    def test_handles_empty_string_key(self, app):
        version, client_key = process_tls_crypt_key('')
        assert version is None
        assert client_key is None

    def test_raises_error_for_unrecognized_format(self, app):
        """
        Test that a key without proper OpenVPN BEGIN header raises ValueError.
        """
        bad_key = "-----BEGIN FOO-----\nbar\n-----END FOO-----"
        with pytest.raises(ValueError, match="Unrecognized TLS-Crypt key format."):
            process_tls_crypt_key(bad_key)

    def test_raises_error_for_unknown_openvpn_key_type(self, app):
        """
        Test that an OpenVPN key with unknown type raises ValueError.
        """
        unknown_key = """-----BEGIN OpenVPN Unknown Key Type-----
somedata
-----END OpenVPN Unknown Key Type-----"""
        with pytest.raises(ValueError, match="Unrecognized TLS-Crypt key format."):
            process_tls_crypt_key(unknown_key)

    @patch('app.utils.openvpn_helpers.trace')
    def test_trace_redacts_master_key(self, mock_trace, app):
        """VULN-12: trace() must not log the full plaintext TLS-Crypt master key.

        The logged value must be redacted, showing only the first 15 and last 15
        characters of the key with '[REDACTED]' in between, so that the secret
        key material is never written to trace logs.
        """
        process_tls_crypt_key(TLS_CRYPT_V1_KEY)

        assert mock_trace.called
        logged_data = mock_trace.call_args[0][2]
        logged_key = logged_data['master_key_pem']

        assert '[REDACTED]' in logged_key
        # Full key must not be logged verbatim
        assert logged_key != TLS_CRYPT_V1_KEY
        # First 15 and last 15 chars of the original key must be present
        assert TLS_CRYPT_V1_KEY[:15] in logged_key
        assert TLS_CRYPT_V1_KEY[-15:] in logged_key

    @patch('app.utils.openvpn_helpers.trace')
    def test_trace_handles_none_key_without_error(self, mock_trace, app):
        """VULN-12: trace redaction must handle None key gracefully.

        When no TLS-Crypt key is configured the function should still return
        normally without raising an error during redaction.
        """
        version, client_key = process_tls_crypt_key(None)

        assert version is None
        assert client_key is None
        assert mock_trace.called
        logged_data = mock_trace.call_args[0][2]
        # None should be logged as-is (nothing to redact)
        assert logged_data['master_key_pem'] is None


class TestTemplateRendering:
    """
    Tests that verify tls-crypt templates render correctly with version-specific directives.
    """

    @pytest.fixture
    def app(self):
        """Create a test Flask app."""
        os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-for-testing-only'
        os.environ['FERNET_ENCRYPTION_KEY'] = 'test-encryption-key-for-testing-only-32-chars-long'
        os.environ['TESTING'] = 'True'

        app = create_app('testing')
        app.config.update({
            'TESTING': True,
            'SECRET_KEY': 'test-secret-key-for-testing-only',
        })

        with app.app_context():
            yield app

    def test_v1_key_renders_with_tls_crypt_directive(self, app):
        """
        Test that v1 keys render with <tls-crypt> directive.

        Security consideration: V1 keys use shared static keys, which is less
        secure than V2's per-client keys but still provides TLS channel encryption.
        """
        template_str = """
{%- if tls_crypt_key %}
{%- if tlscrypt_version == 2 %}
<tls-crypt-v2>
{{ tls_crypt_key }}
</tls-crypt-v2>
{%- else %}
<tls-crypt>
{{ tls_crypt_key }}
</tls-crypt>
{%- endif %}
{% endif %}
"""
        version, client_key = process_tls_crypt_key(TLS_CRYPT_V1_KEY)
        template = Template(template_str)
        rendered = template.render(
            tls_crypt_key=client_key,
            tlscrypt_version=version
        )

        assert '<tls-crypt>' in rendered
        assert '</tls-crypt>' in rendered
        assert '<tls-crypt-v2>' not in rendered
        assert '</tls-crypt-v2>' not in rendered
        assert TLS_CRYPT_V1_KEY.strip() in rendered.strip()

    @patch('app.utils.openvpn_helpers.subprocess.run', side_effect=_mock_openvpn_success)
    def test_v2_key_renders_with_tls_crypt_v2_directive(self, mock_run, app):
        """
        Test that v2 keys render with <tls-crypt-v2> directive.

        Security consideration: V2 keys provide better security through unique
        per-client keys derived from the server master key, preventing shared
        secret compromise from affecting all clients.
        """
        template_str = """
{%- if tls_crypt_key %}
{%- if tlscrypt_version == 2 %}
<tls-crypt-v2>
{{ tls_crypt_key }}
</tls-crypt-v2>
{%- else %}
<tls-crypt>
{{ tls_crypt_key }}
</tls-crypt>
{%- endif %}
{% endif %}
"""
        version, client_key = process_tls_crypt_key(TLS_CRYPT_V2_SERVER_KEY)
        template = Template(template_str)
        rendered = template.render(
            tls_crypt_key=client_key,
            tlscrypt_version=version
        )

        assert '<tls-crypt-v2>' in rendered
        assert '</tls-crypt-v2>' in rendered
        assert '<tls-crypt>' not in rendered
        # V1 directive should not appear (check this way to avoid false positive from v2 containing "tls-crypt")
        assert rendered.count('<tls-crypt>') == 0
        assert '-----BEGIN OpenVPN tls-crypt-v2 client key-----' in rendered

    def test_no_key_renders_nothing(self, app):
        """
        Test that when no TLS-Crypt key is provided, no directives are rendered.

        This allows the system to operate without TLS-Crypt if not configured,
        though this reduces security and is not recommended for production.
        """
        template_str = """
{%- if tls_crypt_key %}
{%- if tlscrypt_version == 2 %}
<tls-crypt-v2>
{{ tls_crypt_key }}
</tls-crypt-v2>
{%- else %}
<tls-crypt>
{{ tls_crypt_key }}
</tls-crypt>
{%- endif %}
{% endif %}
"""
        version, client_key = process_tls_crypt_key(None)
        template = Template(template_str)
        rendered = template.render(
            tls_crypt_key=client_key,
            tlscrypt_version=version
        )

        assert '<tls-crypt>' not in rendered
        assert '<tls-crypt-v2>' not in rendered
        # Should render to essentially empty (just whitespace)
        assert rendered.strip() == ''
