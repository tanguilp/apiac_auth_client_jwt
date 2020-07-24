# APIacAuthClientJWT

An `APIac.Authenticator` plug that implements the client authentication part of
[RFC7523](https://tools.ietf.org/html/rfc7523) (JSON Web Token (JWT) Profile for OAuth 2.0
Client Authentication and Authorization Grants).

This method consists in sending a MACed or signed JWT in the request body to the OAuth2 token
endpoint, for instance:

```http
POST /token.oauth2 HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=n0esc3NRze7LTCu7iYzS6a5acc3f0ogp4&
client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3A
client-assertion-type%3Ajwt-bearer&
client_assertion=eyJhbGciOiJSUzI1NiIsImtpZCI6IjIyIn0.
eyJpc3Mi[...omitted for brevity...].
cC4hiUPo[...omitted for brevity...]
```

OpenID Connect further specifies the `"client_secret_jwt"` and `"private_key_jwt"`
authentication methods
([OpenID Connect Core 1.0 incorporating errata set 1 - 9. Client Authentication](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication))
refining RFC7523.

## Installation

```elixir
def deps do
  [
    {:apiac_auth_client_jwt, "~> 1.2"}
  ]
end
```

## Example

```elixir
plug APIacAuthClientJWT,
  client_callback: &MyApp.Client.config/1,
  protocol: :rfc7523,
  server_metadata_callback: &MyApp.metadata.get/0
```

## Plug options

- `:iat_max_interval`: the maximum time interval, in seconds, before a token with an `"iat"`
field is considered too far in the past. Defaults to `30`, which means token emitted longer
than 30 seconds ago will be rejected
- `:client_callback` [**mandatory**]: a callback that returns client configuration from its
`client_id`. See below for more details
- `error_response_verbosity`: one of `:debug`, `:normal` or `:minimal`.
Defaults to `:normal`
- `:protocol`: `:rfc7523` or `:oidc`. Defaults to `:oidc`. When using OpenID Connect, the
following additional checks are performed:
  - the `"iss"` JWT field must be the client id
  - the `"jti"` claim must be present
- `:jti_register`: a module implementing the
[`JTIRegister`](https://hexdocs.pm/jti_register/JTIRegister.html) behaviour, to protect
against token replay. Defaults to `nil`, **mandatory** if the protocol is set to `:oidc`
- `:server_metadata_callback` [**mandatory**]: OAuth2 / OpenID Connect server metadata. The
following fields are used:
  - `"token_endpoint"`: the `"aud"` claim of the JWTs must match it
  - `"token_endpoint_auth_signing_alg_values_supported"`: the MAC and signing algorithms
  supported for verifying JWTs
- `set_error_response`: function called when authentication failed. Defaults to
`APIacAuthClientJWT.send_error_response/3`

## Client configuration

The client callback returns a map whose keys are those documented in
[OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata).

This includes the `"client_secret"` field that is used for MACed JWTs.

The `"token_endpoint_auth_method"` is mandatory and must be set to either `"client_secret_jwt"`
or `"private_key_jwt"`.

## Determining allowed signature verification algorithms and keys

Signature verification algorithms:
- if the client's `"token_endpoint_auth_signing_alg"` is set, use this algorithm if it is
allowed by the `"token_endpoint_auth_signing_alg_values_supported"` server metadata, otherwise,
the `"token_endpoint_auth_signing_alg_values_supported"` value if used
- then, the client's `"token_endpoint_auth_method"` is used to filter only relevant algorithms
(MAC algorithms if `"token_endpoint_auth_method"` is set to `"client_secret_jwt"`, signature
algorithms otherwise)

Signature verification keys: if `"token_endpoint_auth_method"` is set to:
- `"client_secret_jwt"`: both the client's `"client_secret"` (if present) and `"jwks"` (if
present) fields are used to create the list of suitable MAC verification keys
- `"private_key_jwt"`: either `"jwks"` or `"jwks_uri"` are used to retrieve suitable signature
verification keys. Note that both fields should not be configured at the same time

## Replay protection

Replay protection can be implemented to prevent a JWT from being reused. This is mandatory when
using OpenID Connect.

The `:jti_register` allows configuring a module that implements the
[`JTIRegister`](https://hexdocs.pm/jti_register/JTIRegister.html) behaviour.

The [`JTIRegister.ETS`](https://hexdocs.pm/jti_register/JTIRegister.ETS.html) implementation
provides with a basic implementation for single node servers.
