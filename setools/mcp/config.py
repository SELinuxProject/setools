# SPDX-License-Identifier: LGPL-2.1-only

import configparser
import enum
import logging
import os
import typing

try:
    from fastmcp.server.auth import (AuthProvider, OAuthProxy, OIDCProxy, RemoteAuthProvider,
                                     TokenVerifier)
    from fastmcp.server.auth.providers.debug import DebugTokenVerifier
    from fastmcp.server.auth.providers.introspection import IntrospectionTokenVerifier
    from fastmcp.server.auth.providers.jwt import JWTVerifier, StaticTokenVerifier
except ImportError as iex:
    logging.getLogger(__name__).debug(f"{iex.name} failed to import.")

from ..exception import (InvalidMCPAuthMethod, InvalidMCPAuthOption, InvalidMCPConfig,
                         InvalidMCPOption)

__all__ = ("AuthMethod", "MCPConfig")

SERVER_SECTION: typing.Final[str] = "server"
AUTH_SECTION: typing.Final[str] = "auth"
METHOD_OPTION: typing.Final[str] = "method"
TOKEN_SUBSECTION: typing.Final[str] = "token"

DEFAULT_HOST: typing.Final[str] = "127.0.0.1"
DEFAULT_PORT: typing.Final[int] = 8000
MIN_PORT: typing.Final[int] = 1
MAX_PORT: typing.Final[int] = 65535


class AuthMethod(str, enum.Enum):

    """FastMCP authentication methods supported by the configuration file."""

    none = "none"
    jwt = "jwt"
    static = "static"
    debug = "debug"
    introspection = "introspection"
    remote = "remote"
    oauth_proxy = "oauth_proxy"
    oidc_proxy = "oidc_proxy"


#: Methods that only verify bearer tokens, usable as a nested token verifier.
VERIFIER_METHODS: typing.Final[frozenset[AuthMethod]] = frozenset((
    AuthMethod.jwt, AuthMethod.static, AuthMethod.debug, AuthMethod.introspection))

#: Methods that require a nested token verifier.
_NEEDS_VERIFIER: typing.Final[frozenset[AuthMethod]] = frozenset((
    AuthMethod.remote, AuthMethod.oauth_proxy))


class ServerOption(str, enum.Enum):

    """Options of the [server] section."""

    host = "host"
    port = "port"


class AuthOption(str, enum.Enum):

    """
    Options of the authentication method sections.

    Except for public_key_file, which is a shorthand for public_key, the values are the
    FastMCP provider constructor parameters the options are passed to.
    """

    algorithm = "algorithm"
    allowed_client_redirect_uris = "allowed_client_redirect_uris"
    audience = "audience"
    authorization_servers = "authorization_servers"
    base_url = "base_url"
    client_id = "client_id"
    client_secret = "client_secret"
    config_url = "config_url"
    consent_csp_policy = "consent_csp_policy"
    fallback_access_token_expiry_seconds = "fallback_access_token_expiry_seconds"
    forward_pkce = "forward_pkce"
    introspection_url = "introspection_url"
    issuer = "issuer"
    issuer_url = "issuer_url"
    jwks_uri = "jwks_uri"
    jwt_signing_key = "jwt_signing_key"
    public_key = "public_key"
    public_key_file = "public_key_file"
    redirect_path = "redirect_path"
    require_authorization_consent = "require_authorization_consent"
    required_scopes = "required_scopes"
    resource_documentation = "resource_documentation"
    resource_name = "resource_name"
    scopes = "scopes"
    service_documentation_url = "service_documentation_url"
    strict = "strict"
    timeout_seconds = "timeout_seconds"
    token_endpoint_auth_method = "token_endpoint_auth_method"
    token_verifier = "token_verifier"
    tokens = "tokens"
    upstream_authorization_endpoint = "upstream_authorization_endpoint"
    upstream_client_id = "upstream_client_id"
    upstream_client_secret = "upstream_client_secret"
    upstream_revocation_endpoint = "upstream_revocation_endpoint"
    upstream_token_endpoint = "upstream_token_endpoint"
    valid_scopes = "valid_scopes"


def _string(value: str) -> str:
    """Strip surrounding whitespace from a configuration value."""
    return value.strip()


def _string_list(value: str) -> list[str]:
    """Convert a comma-separated configuration value to a list of strings."""
    return [i.strip() for i in value.split(",") if i.strip()]


def _string_or_list(value: str) -> str | list[str]:
    """Return a list if the value is comma-separated, otherwise a plain string."""
    return _string_list(value) if "," in value else value.strip()


def _integer(value: str) -> int:
    """Convert a configuration value to an integer."""
    return int(value.strip())


def _boolean(value: str) -> bool:
    """Convert a configuration value to a boolean."""
    try:
        return configparser.ConfigParser.BOOLEAN_STATES[value.strip().lower()]
    except KeyError as ex:
        raise ValueError(f"{value} is not a valid boolean") from ex


def _pem_file(value: str) -> str:
    """Read a PEM value from the file path in a configuration option."""
    with open(value.strip(), "r", encoding="utf-8") as fd:
        return fd.read()


def _kwargs(options: dict[AuthOption, typing.Any]) -> dict[str, typing.Any]:
    """Convert parsed options into FastMCP provider keyword arguments."""
    return {option.value: value for option, value in options.items()}


ValueConverter = typing.Callable[[str], typing.Any]
EnumOption = typing.TypeVar("EnumOption", bound=enum.Enum)

#: Valid options and their value converters for the [server] section.
SERVER_OPTIONS: typing.Final[dict[ServerOption, ValueConverter]] = {
    ServerOption.host: _string,
    ServerOption.port: _integer,
}

#: Valid options and their value converters, per authentication method.
ALL_METHOD_OPTIONS: typing.Final[dict[AuthMethod, dict[AuthOption, ValueConverter]]] = {
    AuthMethod.none: {},
    AuthMethod.jwt: {
        AuthOption.public_key: _string,
        AuthOption.public_key_file: _pem_file,
        AuthOption.jwks_uri: _string,
        AuthOption.issuer: _string_or_list,
        AuthOption.audience: _string_or_list,
        AuthOption.algorithm: _string,
        AuthOption.required_scopes: _string_list,
        AuthOption.base_url: _string,
    },
    AuthMethod.static: {
        AuthOption.required_scopes: _string_list,
    },
    AuthMethod.debug: {
        AuthOption.client_id: _string,
        AuthOption.scopes: _string_list,
        AuthOption.required_scopes: _string_list,
    },
    AuthMethod.introspection: {
        AuthOption.introspection_url: _string,
        AuthOption.client_id: _string,
        AuthOption.client_secret: _string,
        AuthOption.timeout_seconds: _integer,
        AuthOption.required_scopes: _string_list,
        AuthOption.base_url: _string,
    },
    AuthMethod.remote: {
        AuthOption.token_verifier: _string,
        AuthOption.authorization_servers: _string_list,
        AuthOption.base_url: _string,
        AuthOption.resource_name: _string,
        AuthOption.resource_documentation: _string,
    },
    AuthMethod.oauth_proxy: {
        AuthOption.token_verifier: _string,
        AuthOption.upstream_authorization_endpoint: _string,
        AuthOption.upstream_token_endpoint: _string,
        AuthOption.upstream_client_id: _string,
        AuthOption.upstream_client_secret: _string,
        AuthOption.upstream_revocation_endpoint: _string,
        AuthOption.base_url: _string,
        AuthOption.redirect_path: _string,
        AuthOption.issuer_url: _string,
        AuthOption.service_documentation_url: _string,
        AuthOption.allowed_client_redirect_uris: _string_list,
        AuthOption.valid_scopes: _string_list,
        AuthOption.forward_pkce: _boolean,
        AuthOption.token_endpoint_auth_method: _string,
        AuthOption.jwt_signing_key: _string,
        AuthOption.require_authorization_consent: _boolean,
        AuthOption.consent_csp_policy: _string,
        AuthOption.fallback_access_token_expiry_seconds: _integer,
    },
    AuthMethod.oidc_proxy: {
        AuthOption.config_url: _string,
        AuthOption.client_id: _string,
        AuthOption.client_secret: _string,
        AuthOption.audience: _string,
        AuthOption.strict: _boolean,
        AuthOption.timeout_seconds: _integer,
        AuthOption.algorithm: _string,
        AuthOption.required_scopes: _string_list,
        AuthOption.base_url: _string,
        AuthOption.issuer_url: _string,
        AuthOption.redirect_path: _string,
        AuthOption.allowed_client_redirect_uris: _string_list,
        AuthOption.token_endpoint_auth_method: _string,
        AuthOption.require_authorization_consent: _boolean,
        AuthOption.consent_csp_policy: _string,
        AuthOption.fallback_access_token_expiry_seconds: _integer,
    },
}

#: Options that must be present, per authentication method.
REQUIRED_METHOD_OPTIONS: typing.Final[dict[AuthMethod, frozenset[AuthOption]]] = {
    AuthMethod.none: frozenset(),
    AuthMethod.jwt: frozenset(),
    AuthMethod.static: frozenset(),
    AuthMethod.debug: frozenset(),
    AuthMethod.introspection: frozenset((AuthOption.introspection_url, AuthOption.client_id,
                                         AuthOption.client_secret)),
    AuthMethod.remote: frozenset((AuthOption.token_verifier, AuthOption.authorization_servers,
                                  AuthOption.base_url)),
    AuthMethod.oauth_proxy: frozenset((AuthOption.token_verifier,
                                       AuthOption.upstream_authorization_endpoint,
                                       AuthOption.upstream_token_endpoint,
                                       AuthOption.upstream_client_id,
                                       AuthOption.upstream_client_secret,
                                       AuthOption.base_url)),
    AuthMethod.oidc_proxy: frozenset((AuthOption.config_url, AuthOption.client_id,
                                      AuthOption.client_secret, AuthOption.base_url)),
}

#: Key sources accepted by the jwt method; exactly one is required.
_JWT_KEY_OPTIONS: typing.Final[frozenset[AuthOption]] = frozenset((
    AuthOption.public_key, AuthOption.public_key_file, AuthOption.jwks_uri))


class MCPConfig:

    """
    Parser for the MCP server's INI-format configuration.

    The configuration is loaded on construction if a path is provided,
    otherwise the settings are unset until load() is called.
    """

    def __init__(self, path: str | os.PathLike | None = None) -> None:
        """Initialize an empty configuration and optionally load *path*."""
        self.log: logging.Logger = logging.getLogger(__name__)
        self.path: str | None = None
        #: The address for the HTTP transport to bind to.
        self.bind_address: str | None = None
        #: The port for the HTTP transport to bind to.
        self.bind_port: int | None = None
        self.auth_method: AuthMethod = AuthMethod.none
        self.auth_options: dict[AuthOption, typing.Any] = {}
        self.verifier_method: AuthMethod | None = None
        self.verifier_options: dict[AuthOption, typing.Any] = {}

        if path is not None:
            self.load(path)

    def load(self, path: str | os.PathLike) -> None:
        """Load and validate the configuration at *path*."""
        source = os.fspath(path)
        self.log.info(f"Opening MCP config {source}.")

        parser = configparser.ConfigParser()
        try:
            with open(source, "r", encoding="utf-8") as fd:
                parser.read_file(fd, source=source)
        except (OSError, configparser.Error) as ex:
            raise InvalidMCPConfig(f"Unable to parse MCP config {source}: {ex}") from ex

        host, port = self._parse_server(parser)

        method = self._parse_method(parser)
        options = self._parse_auth_options(parser, method.value, method)

        verifier_method: AuthMethod | None = None
        verifier_options: dict[AuthOption, typing.Any] = {}
        if method in _NEEDS_VERIFIER:
            verifier_method = self._parse_verifier_method(options.pop(AuthOption.token_verifier))
            verifier_options = self._parse_auth_options(parser, verifier_method.value,
                                                        verifier_method)

        # Only commit the new settings once the entire file validates.
        self.path = source
        self.bind_address = host
        self.bind_port = port
        self.auth_method = method
        self.auth_options = options
        self.verifier_method = verifier_method
        self.verifier_options = verifier_options

    @property
    def auth_provider(self) -> AuthProvider | None:
        """The FastMCP auth provider described by this configuration."""
        if self.auth_method == AuthMethod.none:
            self.log.warning("MCP server is configured with no authentication, this is insecure.")
            return None

        if self.auth_method in VERIFIER_METHODS:
            return self._create_verifier(self.auth_method, self.auth_options)

        options = _kwargs(self.auth_options)

        # Required constructor arguments are validated by _parse_auth_options().
        if self.auth_method == AuthMethod.oidc_proxy:
            return OIDCProxy(**options)  # pylint: disable=missing-kwoa

        assert self.verifier_method is not None, "No token verifier loaded, this is a bug."
        verifier = self._create_verifier(self.verifier_method, self.verifier_options)

        if self.auth_method == AuthMethod.oauth_proxy:
            return OAuthProxy(token_verifier=verifier,  # pylint: disable=missing-kwoa
                              **options)

        # FastMCP validates the authorization server and documentation URLs.
        return RemoteAuthProvider(token_verifier=verifier, **options)

    #
    # Internal helpers
    #
    def _parse_server(self, parser: configparser.ConfigParser) -> tuple[str, int]:
        """Parse and validate the server bind address and port."""

        options = self._parse_section(parser, SERVER_SECTION, ServerOption, SERVER_OPTIONS,
                                      SERVER_SECTION, InvalidMCPOption)

        port = options.get(ServerOption.port, DEFAULT_PORT)
        if not MIN_PORT <= port <= MAX_PORT:
            raise InvalidMCPOption(f"[{SERVER_SECTION}] {ServerOption.port.value}: {port} is "
                                   "not a valid port number.")

        return options.get(ServerOption.host, DEFAULT_HOST), port

    @staticmethod
    def _parse_method(parser: configparser.ConfigParser) -> AuthMethod:
        """Parse the selected authentication method from the [auth] section."""
        if not parser.has_option(AUTH_SECTION, METHOD_OPTION):
            return AuthMethod.none

        for name in parser.options(AUTH_SECTION):
            if name != METHOD_OPTION:
                raise InvalidMCPAuthOption(f"[{AUTH_SECTION}]: {name} is not a valid "
                                           f"{AUTH_SECTION} option.")

        name = parser.get(AUTH_SECTION, METHOD_OPTION).strip()
        try:
            return AuthMethod(name)
        except ValueError as ex:
            raise InvalidMCPAuthMethod(f"Unknown authentication method: {name}") from ex

    @staticmethod
    def _parse_verifier_method(name: str) -> AuthMethod:
        """Parse and validate a nested token verifier method name."""
        try:
            method = AuthMethod(name)
        except ValueError as ex:
            raise InvalidMCPAuthMethod(f"Unknown token verifier method: {name}") from ex

        if method not in VERIFIER_METHODS:
            raise InvalidMCPAuthMethod(f"{name} is not a token verifier method.")

        return method

    @staticmethod
    def _parse_section(parser: configparser.ConfigParser, section: str,
                       options_enum: type[EnumOption], valid: dict[EnumOption, ValueConverter],
                       kind: str,
                       exception: type[InvalidMCPOption]) -> dict[EnumOption, typing.Any]:
        """Parse one INI section using its option enum and value converters."""

        options: dict[EnumOption, typing.Any] = {}

        if parser.has_section(section):
            for name, value in parser.items(section):
                try:
                    option = options_enum(name)
                    convert = valid[option]
                except (KeyError, ValueError) as ex:
                    raise exception(
                        f"[{section}]: {name} is not a valid {kind} option.") from ex

                try:
                    options[option] = convert(value)
                except (OSError, ValueError) as ex:
                    raise exception(f"[{section}] {name}: {ex}") from ex

        return options

    def _parse_auth_options(self, parser: configparser.ConfigParser, section: str,
                            method: AuthMethod) -> dict[AuthOption, typing.Any]:
        """Parse and validate options for one authentication method."""

        options = self._parse_section(parser, section, AuthOption, ALL_METHOD_OPTIONS[method],
                                      method.value, InvalidMCPAuthOption)

        if method == AuthMethod.static:
            options[AuthOption.tokens] = self._parse_tokens(parser, section)

        missing = REQUIRED_METHOD_OPTIONS[method] - options.keys()
        if missing:
            raise InvalidMCPAuthOption(f"[{section}]: missing required {method.value} options: "
                                       f"{', '.join(sorted(o.value for o in missing))}")

        if method == AuthMethod.jwt:
            if not options.keys() & _JWT_KEY_OPTIONS:
                raise InvalidMCPAuthOption(
                    f"[{section}]: one of "
                    f"{', '.join(sorted(o.value for o in _JWT_KEY_OPTIONS))} is required.")

            if AuthOption.public_key_file in options:
                options[AuthOption.public_key] = options.pop(AuthOption.public_key_file)

        return options

    @staticmethod
    def _parse_tokens(parser: configparser.ConfigParser,
                      section: str) -> dict[str, dict[str, typing.Any]]:
        """Parse [<section>.token.<token>] subsections into static token claims."""
        prefix = f"{section}.{TOKEN_SUBSECTION}."
        tokens: dict[str, dict[str, typing.Any]] = {}

        for name in parser.sections():
            if not name.startswith(prefix):
                continue

            token = name[len(prefix):].strip()
            if not token:
                raise InvalidMCPAuthOption(f"[{name}]: token subsection has no token value.")

            # The claim names are not fixed, so they are passed through to FastMCP as given.
            claims: dict[str, typing.Any] = dict(parser.items(name))
            scopes = AuthOption.scopes.value
            if scopes in claims:
                claims[scopes] = _string_list(claims[scopes])

            tokens[token] = claims

        if not tokens:
            raise InvalidMCPAuthOption(f"[{prefix}<token>]: at least one token is required "
                                       "for static.")

        return tokens

    @staticmethod
    def _create_verifier(method: AuthMethod,
                         options: dict[AuthOption, typing.Any]) -> "TokenVerifier":
        """Create a token verifier from parsed authentication options."""

        kwargs = _kwargs(options)
        match method:
            case AuthMethod.jwt:
                return JWTVerifier(**kwargs)
            case AuthMethod.static:
                return StaticTokenVerifier(**kwargs)
            case AuthMethod.debug:
                return DebugTokenVerifier(**kwargs)
            case AuthMethod.introspection:
                return IntrospectionTokenVerifier(**kwargs)
            case _:
                raise InvalidMCPAuthMethod(f"{method.value} is not a token verifier method.")
