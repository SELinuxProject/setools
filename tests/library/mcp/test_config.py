# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for setools.mcp.config.MCPConfig."""

import pathlib

import pytest

from setools.exception import (InvalidMCPAuthMethod, InvalidMCPAuthOption, InvalidMCPConfig,
                               InvalidMCPOption)
from setools.mcp.config import AuthMethod, AuthOption, MCPConfig

DOCS = pathlib.Path(__file__).parents[3] / "docs"


@pytest.fixture
def config_file(tmp_path):
    """Write *text* to a temporary INI file and return its path."""
    def _write(text: str, name: str = "mcp.ini"):
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        return path

    return _write


class TestMCPConfigLoading:

    """Tests for construction and the load() method."""

    def test_no_path(self):
        """Config settings are unset when no path is given."""
        config = MCPConfig()
        assert config.path is None
        assert config.bind_address is None
        assert config.bind_port is None
        assert config.auth_provider is None
        assert config.auth_method == AuthMethod.none
        assert not config.auth_options
        assert config.verifier_method is None
        assert not config.verifier_options

    def test_load_on_init(self, config_file):
        """Config is loaded by the constructor when a path is given."""
        path = config_file(
            "[auth]\n"
            "method = debug\n")
        config = MCPConfig(path)
        assert config.path == str(path)
        assert config.auth_method == AuthMethod.debug

    def test_load_method(self, config_file):
        """load() replaces the settings of an existing config."""
        config = MCPConfig(config_file(
            "[auth]\n"
            "method = debug\n"))
        config.load(config_file(
            "[auth]\n"
            "method = none\n", name="other.ini"))
        assert config.auth_method == AuthMethod.none

    def test_load_failure_keeps_settings(self, config_file):
        """A failed load() leaves the previous settings intact."""
        good = config_file(
            "[server]\n"
            "port = 9000\n"
            "[auth]\n"
            "method = debug\n"
            "[debug]\n"
            "client_id = a\n")
        bad = config_file(
            "[auth]\n"
            "method = bogus\n", name="bad.ini")
        config = MCPConfig(good)

        with pytest.raises(InvalidMCPAuthMethod):
            config.load(bad)

        assert config.path == str(good)
        assert config.bind_port == 9000
        assert config.auth_method == AuthMethod.debug
        assert config.auth_options == {AuthOption.client_id: "a"}

    def test_missing_file(self, tmp_path):
        """A nonexistent config file is an error."""
        with pytest.raises(InvalidMCPConfig):
            MCPConfig(tmp_path / "does-not-exist.ini")

    def test_malformed_file(self, config_file):
        """A file that is not valid INI is an error."""
        with pytest.raises(InvalidMCPConfig):
            MCPConfig(config_file("this is not an ini file\n"))

    def test_missing_auth_section(self, config_file):
        """Authentication is disabled when the [auth] section is absent."""
        config = MCPConfig(config_file(
            "[server]\n"
            "port = 9000\n"))
        assert config.auth_method == AuthMethod.none

    def test_missing_method(self, config_file):
        """Authentication is disabled when the method option is absent."""
        config = MCPConfig(config_file("[auth]\n"))
        assert config.auth_method == AuthMethod.none

    def test_unknown_auth_option(self, config_file):
        """The [auth] section accepts no option other than method."""
        with pytest.raises(InvalidMCPAuthOption):
            MCPConfig(config_file(
                "[auth]\n"
                "method = none\n"
                "bogus = x\n"))

    def test_unknown_method(self, config_file):
        """An unknown method is an error."""
        with pytest.raises(InvalidMCPAuthMethod):
            MCPConfig(config_file(
                "[auth]\n"
                "method = oauth_provider\n"))

    def test_unknown_option(self, config_file):
        """An option not valid for the method is an error."""
        with pytest.raises(InvalidMCPAuthOption):
            MCPConfig(config_file(
                "[auth]\n"
                "method = debug\n"
                "[debug]\n"
                "bogus = x\n"))


class TestMCPConfigServer:

    """Tests for the [server] section."""

    def test_defaults(self, config_file):
        """The bind address defaults to the loopback address and port 8000."""
        config = MCPConfig(config_file(
            "[auth]\n"
            "method = none\n"))
        assert config.bind_address == "127.0.0.1"
        assert config.bind_port == 8000

    def test_options(self, config_file):
        """The listening address and port are parsed."""
        config = MCPConfig(config_file(
            "[server]\n"
            "host = 192.0.2.1\n"
            "port = 9000\n"))

        assert config.bind_address == "192.0.2.1"
        assert config.bind_port == 9000

    def test_unknown_option(self, config_file):
        """An unknown server option is an error."""
        with pytest.raises(InvalidMCPOption):
            MCPConfig(config_file(
                "[server]\n"
                "bogus = x\n"))

    def test_invalid_port(self, config_file):
        """A non-integer port is an error."""
        with pytest.raises(InvalidMCPOption):
            MCPConfig(config_file(
                "[server]\n"
                "port = http\n"))

    @pytest.mark.parametrize("port", ("0", "65536", "-1"))
    def test_out_of_range_port(self, config_file, port):
        """A port outside the valid range is an error."""
        with pytest.raises(InvalidMCPOption):
            MCPConfig(config_file(
                f"[server]\n"
                "port = {port}\n"))


class TestMCPConfigAuthNone:

    """Tests for the none method."""

    def test_none(self, config_file):
        """No authentication has no options and no provider."""
        config = MCPConfig(config_file(
            "[auth]\n"
            "method = none\n"))
        assert config.auth_method == AuthMethod.none
        assert not config.auth_options
        assert config.auth_provider is None


class TestMCPConfigAuthJWT:

    """Tests for the jwt method."""

    def test_jwks(self, config_file):
        """JWKS options are parsed and converted."""
        config = MCPConfig(config_file(
            "[auth]\n"
            "method = jwt\n"
            "[jwt]\n"
            "jwks_uri = https://auth.example.com/jwks\n"
            "issuer = https://auth.example.com\n"
            "audience = setools-mcp\n"
            "algorithm = ES256\n"
            "required_scopes = setools:read, setools:analyze\n"))

        assert config.auth_method == AuthMethod.jwt
        assert config.auth_options == {
            AuthOption.jwks_uri: "https://auth.example.com/jwks",
            AuthOption.issuer: "https://auth.example.com",
            AuthOption.audience: "setools-mcp",
            AuthOption.algorithm: "ES256",
            AuthOption.required_scopes: ["setools:read", "setools:analyze"]}

    def test_multiple_audiences(self, config_file):
        """A comma-separated audience is parsed into a list."""
        config = MCPConfig(config_file(
            "[auth]\n"
            "method = jwt\n"
            "[jwt]\n"
            "jwks_uri = https://auth.example.com/jwks\n"
            "audience = setools-mcp, other-mcp\n"))

        assert config.auth_options[AuthOption.audience] == ["setools-mcp", "other-mcp"]

    def test_public_key_file(self, config_file, tmp_path):
        """public_key_file is read and mapped onto public_key."""
        key = tmp_path / "key.pem"
        key.write_text(
            "-----BEGIN PUBLIC KEY-----\n"
            "AAAA\n"
            "-----END PUBLIC KEY-----\n",
            encoding="utf-8")
        config = MCPConfig(config_file(
            "[auth]\n"
            "method = jwt\n"
            "[jwt]\n"
            f"public_key_file = {key}\n"))

        assert AuthOption.public_key_file not in config.auth_options
        assert config.auth_options[AuthOption.public_key].startswith("-----BEGIN PUBLIC KEY-----")

    def test_unreadable_public_key_file(self, config_file, tmp_path):
        """An unreadable public_key_file is an error."""
        with pytest.raises(InvalidMCPAuthOption):
            MCPConfig(config_file(
                "[auth]\n"
                "method = jwt\n"
                "[jwt]\n"
                f"public_key_file = {tmp_path / 'missing'}\n"))

    def test_no_key_source(self, config_file):
        """One of public_key, public_key_file, or jwks_uri is required."""
        with pytest.raises(InvalidMCPAuthOption):
            MCPConfig(config_file(
                "[auth]\n"
                "method = jwt\n"
                "[jwt]\n"
                "issuer = https://x.com\n"))

    def test_no_section(self, config_file):
        """A jwt config with no [jwt] section is an error."""
        with pytest.raises(InvalidMCPAuthOption):
            MCPConfig(config_file(
                "[auth]\n"
                "method = jwt\n"))


class TestMCPConfigAuthStatic:

    """Tests for the static method."""

    def test_tokens(self, config_file):
        """Token subsections are parsed into claim dictionaries."""
        config = MCPConfig(config_file(
            "[auth]\n"
            "method = static\n"
            "[static]\n"
            "required_scopes = setools:read\n"
            "[static.token.token-a]\n"
            "client_id = alice\n"
            "scopes = setools:read, setools:analyze\n"
            "[static.token.token-b]\n"
            "client_id = bob\n"
            "scopes = setools:read\n"))

        assert config.auth_options[AuthOption.required_scopes] == ["setools:read"]
        assert config.auth_options[AuthOption.tokens] == {
            "token-a": {"client_id": "alice",
                        "scopes": ["setools:read", "setools:analyze"]},
            "token-b": {"client_id": "bob", "scopes": ["setools:read"]}}

    def test_no_tokens(self, config_file):
        """At least one token is required."""
        with pytest.raises(InvalidMCPAuthOption):
            MCPConfig(config_file(
                "[auth]\n"
                "method = static\n"
                "[static]\n"))


class TestMCPConfigAuthDebug:

    """Tests for the debug method."""

    def test_options(self, config_file):
        """Debug options are parsed."""
        config = MCPConfig(config_file(
            "[auth]\n"
            "method = debug\n"
            "[debug]\n"
            "client_id = debug-client\n"
            "scopes = a, b\n"
            "required_scopes = a\n"))

        assert config.auth_options == {AuthOption.client_id: "debug-client",
                                       AuthOption.scopes: ["a", "b"],
                                       AuthOption.required_scopes: ["a"]}

    def test_no_section(self, config_file):
        """Debug has no required options."""
        config = MCPConfig(config_file(
            "[auth]\n"
            "method = debug\n"))
        assert not config.auth_options


class TestMCPConfigAuthIntrospection:

    """Tests for the introspection method."""

    def test_options(self, config_file):
        """Introspection options are parsed and converted."""
        config = MCPConfig(config_file(
            "[auth]\n"
            "method = introspection\n"
            "[introspection]\n"
            "introspection_url = https://auth.example.com/introspect\n"
            "client_id = setools-mcp\n"
            "client_secret = secret\n"
            "timeout_seconds = 15\n"
            "required_scopes = setools:read\n"))

        assert config.auth_options == {
            AuthOption.introspection_url: "https://auth.example.com/introspect",
            AuthOption.client_id: "setools-mcp",
            AuthOption.client_secret: "secret",
            AuthOption.timeout_seconds: 15,
            AuthOption.required_scopes: ["setools:read"]}

    def test_missing_required(self, config_file):
        """Missing required options are an error."""
        with pytest.raises(InvalidMCPAuthOption):
            MCPConfig(config_file(
                "[auth]\n"
                "method = introspection\n"
                "[introspection]\n"
                "introspection_url = https://auth.example.com/introspect\n"))

    def test_invalid_integer(self, config_file):
        """A non-integer integer option is an error."""
        with pytest.raises(InvalidMCPAuthOption):
            MCPConfig(config_file(
                "[auth]\n"
                "method = introspection\n"
                "[introspection]\n"
                "introspection_url = https://auth.example.com/introspect\n"
                "client_id = a\n"
                "client_secret = b\n"
                "timeout_seconds = soon\n"))


class TestMCPConfigAuthRemote:

    """Tests for the remote method."""

    def test_options(self, config_file):
        """Remote options and the nested verifier are parsed."""
        config = MCPConfig(config_file(
            "[auth]\n"
            "method = remote\n"
            "[remote]\n"
            "token_verifier = jwt\n"
            "authorization_servers = https://auth.example.com, https://auth2.example.com\n"
            "base_url = https://setools.example.com\n"
            "resource_name = SETools MCP Server\n"
            "[jwt]\n"
            "jwks_uri = https://auth.example.com/jwks\n"))

        assert AuthOption.token_verifier not in config.auth_options
        assert config.auth_options == {
            AuthOption.authorization_servers: ["https://auth.example.com",
                                               "https://auth2.example.com"],
            AuthOption.base_url: "https://setools.example.com",
            AuthOption.resource_name: "SETools MCP Server"}
        assert config.verifier_method == AuthMethod.jwt
        assert config.verifier_options == {
            AuthOption.jwks_uri: "https://auth.example.com/jwks"}

    def test_missing_verifier(self, config_file):
        """token_verifier is required."""
        with pytest.raises(InvalidMCPAuthOption):
            MCPConfig(config_file(
                "[auth]\n"
                "method = remote\n"
                "[remote]\n"
                "authorization_servers = https://auth.example.com\n"
                "base_url = https://setools.example.com\n"))

    def test_unknown_verifier(self, config_file):
        """An unknown token_verifier method is an error."""
        with pytest.raises(InvalidMCPAuthMethod):
            MCPConfig(config_file(
                "[auth]\n"
                "method = remote\n"
                "[remote]\n"
                "token_verifier = bogus\n"
                "authorization_servers = https://auth.example.com\n"
                "base_url = https://setools.example.com\n"))

    def test_non_verifier_method(self, config_file):
        """A method that is not a token verifier cannot be nested."""
        with pytest.raises(InvalidMCPAuthMethod):
            MCPConfig(config_file(
                "[auth]\n"
                "method = remote\n"
                "[remote]\n"
                "token_verifier = oidc_proxy\n"
                "authorization_servers = https://auth.example.com\n"
                "base_url = https://setools.example.com\n"))

    def test_invalid_verifier_option(self, config_file):
        """Options in the nested verifier section are validated."""
        with pytest.raises(InvalidMCPAuthOption):
            MCPConfig(config_file(
                "[auth]\n"
                "method = remote\n"
                "[remote]\n"
                "token_verifier = jwt\n"
                "authorization_servers = https://auth.example.com\n"
                "base_url = https://setools.example.com\n"
                "[jwt]\n"
                "jwks_uri = https://auth.example.com/jwks\n"
                "bogus = x\n"))


class TestMCPConfigAuthOAuthProxy:

    """Tests for the oauth_proxy method."""

    def test_options(self, config_file):
        """OAuth proxy options are parsed and converted."""
        config = MCPConfig(config_file(
            "[auth]\n"
            "method = oauth_proxy\n"
            "[oauth_proxy]\n"
            "token_verifier = jwt\n"
            "upstream_authorization_endpoint = https://auth.example.com/authorize\n"
            "upstream_token_endpoint = https://auth.example.com/token\n"
            "upstream_client_id = id\n"
            "upstream_client_secret = secret\n"
            "base_url = https://setools.example.com\n"
            "allowed_client_redirect_uris = http://localhost:*, http://127.0.0.1:*\n"
            "forward_pkce = no\n"
            "fallback_access_token_expiry_seconds = 3600\n"
            "[jwt]\n"
            "jwks_uri = https://auth.example.com/jwks\n"))

        assert config.auth_options[AuthOption.forward_pkce] is False
        assert config.auth_options[AuthOption.fallback_access_token_expiry_seconds] == 3600
        assert config.auth_options[AuthOption.allowed_client_redirect_uris] == [
            "http://localhost:*", "http://127.0.0.1:*"]
        assert config.verifier_method == AuthMethod.jwt

    def test_missing_required(self, config_file):
        """Missing required options are an error."""
        with pytest.raises(InvalidMCPAuthOption):
            MCPConfig(config_file(
                "[auth]\n"
                "method = oauth_proxy\n"
                "[oauth_proxy]\n"
                "token_verifier = jwt\n"
                "base_url = https://setools.example.com\n"
                "[jwt]\n"
                "jwks_uri = https://auth.example.com/jwks\n"))

    def test_invalid_boolean(self, config_file):
        """A non-boolean boolean option is an error."""
        with pytest.raises(InvalidMCPAuthOption):
            MCPConfig(config_file(
                "[auth]\n"
                "method = oauth_proxy\n"
                "[oauth_proxy]\n"
                "token_verifier = jwt\n"
                "upstream_authorization_endpoint = https://auth.example.com/authorize\n"
                "upstream_token_endpoint = https://auth.example.com/token\n"
                "upstream_client_id = id\n"
                "upstream_client_secret = secret\n"
                "base_url = https://setools.example.com\n"
                "forward_pkce = maybe\n"
                "[jwt]\n"
                "jwks_uri = https://auth.example.com/jwks\n"))


class TestMCPConfigAuthOIDCProxy:

    """Tests for the oidc_proxy method."""

    def test_options(self, config_file):
        """OIDC proxy options are parsed and converted."""
        config = MCPConfig(config_file(
            "[auth]\n"
            "method = oidc_proxy\n"
            "[oidc_proxy]\n"
            "config_url = https://auth.example.com/.well-known/openid-configuration\n"
            "client_id = id\n"
            "client_secret = secret\n"
            "base_url = https://setools.example.com\n"
            "strict = true\n"
            "timeout_seconds = 10\n"
            "required_scopes = openid\n"))

        assert config.auth_options[AuthOption.strict] is True
        assert config.auth_options[AuthOption.timeout_seconds] == 10
        assert config.auth_options[AuthOption.required_scopes] == ["openid"]
        assert config.verifier_method is None

    def test_missing_required(self, config_file):
        """Missing required options are an error."""
        with pytest.raises(InvalidMCPAuthOption):
            MCPConfig(config_file(
                "[auth]\n"
                "method = oidc_proxy\n"
                "[oidc_proxy]\n"
                "client_id = id\n"
                "client_secret = secret\n"))


class TestMCPConfigAuthExamples:

    """The shipped example configurations must parse."""

    @pytest.mark.parametrize("name", ("none", "jwt", "static", "debug", "introspection",
                                      "remote", "oauth-proxy", "oidc-proxy"))
    def test_example(self, name):
        """Each documented example is a valid configuration."""
        config = MCPConfig(DOCS / f"mcp-auth-{name}.ini")
        assert config.auth_method == AuthMethod(name.replace("-", "_"))


class TestMCPConfigAuthProvider:

    """Tests for constructing FastMCP auth providers."""

    def test_jwt(self, config_file):
        """A jwt config creates a JWTVerifier."""
        jwt = pytest.importorskip("fastmcp.server.auth.providers.jwt")
        config = MCPConfig(config_file(
            "[auth]\n"
            "method = jwt\n"
            "[jwt]\n"
            "jwks_uri = https://auth.example.com/jwks\n"))

        assert isinstance(config.auth_provider, jwt.JWTVerifier)

    def test_static(self, config_file):
        """A static config creates a StaticTokenVerifier with the parsed tokens."""
        jwt = pytest.importorskip("fastmcp.server.auth.providers.jwt")
        config = MCPConfig(config_file(
            "[auth]\n"
            "method = static\n"
            "[static.token.token-a]\n"
            "client_id = alice\n"
            "scopes = setools:read\n"))

        provider = config.auth_provider
        assert isinstance(provider, jwt.StaticTokenVerifier)
        assert "token-a" in provider.tokens

    def test_debug(self, config_file):
        """A debug config creates a DebugTokenVerifier."""
        debug = pytest.importorskip("fastmcp.server.auth.providers.debug")
        config = MCPConfig(config_file(
            "[auth]\n"
            "method = debug\n"))

        assert isinstance(config.auth_provider, debug.DebugTokenVerifier)

    def test_remote(self, config_file):
        """A remote config creates a RemoteAuthProvider wrapping the nested verifier."""
        auth = pytest.importorskip("fastmcp.server.auth")
        jwt = pytest.importorskip("fastmcp.server.auth.providers.jwt")
        config = MCPConfig(config_file(
            "[auth]\n"
            "method = remote\n"
            "[remote]\n"
            "token_verifier = jwt\n"
            "authorization_servers = https://auth.example.com\n"
            "base_url = https://setools.example.com\n"
            "[jwt]\n"
            "jwks_uri = https://auth.example.com/jwks\n"))

        provider = config.auth_provider
        assert isinstance(provider, auth.RemoteAuthProvider)
        assert isinstance(provider.token_verifier, jwt.JWTVerifier)
        assert provider.authorization_servers == ["https://auth.example.com"]
