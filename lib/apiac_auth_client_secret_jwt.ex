defmodule APIacAuthClientJWT do
  @moduledoc """
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
  - `:jti_register`: a module that saves JWTes' `"jti"` until expiration to prevent replay.
  Defaults to `nil`, **mandatory** if the protocol is set to `:oidc`
  - `:server_metadata_callback` [**mandatory**]: OAuth2 / OpenID Connect server metadata. The
  following fields are used:
    - `"token_endpoint"`: the `"aud"` (and `"sub"` for OIDC) claim of the JWTs must match it
    - `"token_endpoint_auth_signing_alg_values_supported"`: the MAC and signing algorithms
    supported for verifying JWTs
  - `set_error_response`: function called when authentication failed. Defaults to
  `APIacAuthClientJWT.send_error_response/3`

  Options are documented in `t:opts/0`.

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
  `APIacAuthClientJWT.JTIRegister` behaviour.

  The `APIacAuthClientJWT` library provides with a basic implementation for testing purpose only:
  `APIacAuthClientJWT.JTIRegister.ETS`.
  """

  @assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  @jws_mac_algs ["HS256", "HS384", "HS512"]
  @jws_sig_algs [
    "Ed25519",
    "Ed448",
    "EdDSA",
    "ES256",
    "ES384",
    "ES512",
    "Poly1305",
    "PS256",
    "PS384",
    "PS512",
    "RS256",
    "RS384",
    "RS512"
  ]

  @type opts :: [opt()]

  @type opt ::
          {:iat_max_interval, non_neg_integer()}
          | {:client_callback, (client_id :: String.t() -> client_config())}
          | {:error_response_verbosity, :debug | :normal | :minimal}
          | {:protocol, :rfc7523 | :oidc}
          | {:jti_register, module()}
          | {:server_metadata_callback, (() -> server_metadata())}
          | {:set_error_response,
             (Plug.Conn.t(), %APIac.Authenticator.Unauthorized{}, any() -> Plug.Conn.t())}

  @type client_config :: %{required(String.t()) => any()}

  @type server_metadata :: %{required(String.t()) => any()}

  @behaviour Plug
  @behaviour APIac.Authenticator

  @impl Plug
  def init(opts) do
    unless opts[:client_callback] || is_function(opts[:client_callback], 1),
      do: raise("missing mandatory client callback")

    unless opts[:server_metadata_callback] || is_function(opts[:server_metadata_callback], 0),
      do: raise("missing mandatory server metadata callback")

    opts =
      opts
      |> Keyword.put_new(:error_response_verbosity, :normal)
      |> Keyword.put_new(:iat_max_interval, 30)
      |> Keyword.put_new(:jti_register, nil)
      |> Keyword.put_new(:protocol, :oidc)
      |> Keyword.put_new(:set_error_response, &send_error_response/3)

    if opts[:protocol] == :oidc and opts[:jti_register] == nil,
      do: raise("missing replay protection implementation module, mandatory when OIDC is used")

    opts
  end

  @impl Plug
  def call(conn, opts) do
    if APIac.authenticated?(conn) do
      conn
    else
      do_call(conn, opts)
    end
  end

  def do_call(conn, opts) do
    with {:ok, conn, credentials} <- extract_credentials(conn, opts),
         {:ok, conn} <- validate_credentials(conn, credentials, opts) do
      conn
    else
      {:error, conn, %APIac.Authenticator.Unauthorized{} = error} ->
        opts[:set_error_response].(conn, error, opts)
    end
  end

  @impl APIac.Authenticator
  def extract_credentials(conn, _opts) do
    case conn.body_params do
      %{"client_assertion_type" => @assertion_type, "client_assertion" => client_assertion} ->
        {:ok, conn, client_assertion}

      _ ->
        {
          :error,
          conn,
          %APIac.Authenticator.Unauthorized{
            authenticator: __MODULE__,
            reason: :credentials_not_found
          }
        }
    end
  end

  @impl APIac.Authenticator
  def validate_credentials(conn, client_assertion, opts) do
    with {:ok, client_id} <- get_client_id(conn, client_assertion),
         client_config = opts[:client_callback].(client_id),
         server_metadata = opts[:server_metadata_callback].(),
         verification_algs = verification_algs(client_config, server_metadata),
         verification_keys = verification_keys(client_config, verification_algs),
         {:ok, jwt_claims} <- verify_jwt(client_assertion, verification_keys, verification_algs),
         :ok <- validate_claims(jwt_claims, server_metadata, opts),
         :ok <- check_jwt_not_replayed(jwt_claims, opts) do
      if jwt_claims["jti"] && opts[:jti_register] do
        opts[:jti_register].register(jwt_claims["jti"], jwt_claims["exp"])
      end

      conn =
        conn
        |> Plug.Conn.put_private(:apiac_authenticator, __MODULE__)
        |> Plug.Conn.put_private(:apiac_client, client_id)

      {:ok, conn}
    else
      {:error, reason} ->
        {
          :error,
          conn,
          %APIac.Authenticator.Unauthorized{authenticator: __MODULE__, reason: reason}
        }
    end
  end

  @spec get_client_id(Plug.Conn.t(), String.t()) :: {:ok, String.t()} | {:error, atom()}
  defp get_client_id(conn, client_assertion) do
    jwt_issuer =
      client_assertion
      |> JOSE.JWS.peek_payload()
      |> Jason.decode!()
      |> Map.get("iss")

    case conn.body_params do
      %{"client_id" => client_id} when client_id != jwt_issuer ->
        {:error, :client_id_jwt_issuer_mismatch}

      _ ->
        {:ok, jwt_issuer}
    end
  rescue
    _ ->
      {:error, :invalid_jwt_payload}
  end

  @spec verification_algs(client_config(), server_metadata()) :: [JOSEUtils.JWA.sig_alg()]
  defp verification_algs(client_config, server_metadata) do
    server_algs = server_metadata["token_endpoint_auth_signing_alg_values_supported"] || []
    client_alg = client_config["token_endpoint_auth_signing_alg"]

    cond do
      client_alg == "none" ->
        "illegal client `token_endpoint_auth_signing_alg` used: `none`"

      client_alg in server_algs ->
        [client_alg]

      client_alg != nil ->
        []

      true ->
        server_algs
    end
    |> Enum.filter(fn alg ->
      case client_config["token_endpoint_auth_method"] do
        "client_secret_jwt" ->
          alg in @jws_mac_algs

        "private_key_jwt" ->
          alg in @jws_sig_algs
      end
    end)
  end

  @spec verification_keys(client_config(), [JOSEUtils.JWA.sig_alg()]) :: [JOSEUtils.JWK.t()]
  defp verification_keys(client_config, algs) do
    case client_config["token_endpoint_auth_method"] do
      "client_secret_jwt" ->
        client_mac_jwks(client_config)

      "private_key_jwt" ->
        client_asymmetric_keys(client_config)
    end
    |> JOSEUtils.JWKS.verification_keys(algs)
  end

  @spec client_mac_jwks(client_config()) :: [JOSEUtils.JWK.t()]
  defp client_mac_jwks(client_config) do
    mac_jwks =
      Enum.filter(
        client_config["jwks"] || [],
        fn jwk -> jwk["kty"] == "oct" end
      )

    case client_config do
      %{"client_secret" => client_secret} ->
        [%{"k" => Base.url_encode64(client_secret, padding: false), "kty" => "oct"}] ++ mac_jwks

      _ ->
        mac_jwks
    end
  end

  @spec client_asymmetric_keys(client_config) :: [JOSEUtils.JWK.t()]
  defp client_asymmetric_keys(client_config) do
    case client_config do
      %{"jwks" => jwks} ->
        Enum.filter(jwks, fn jwk -> jwk["kty"] != "oct" end)

      %{"jwks_uri" => jwks_uri} ->
        case JWKSURIUpdater.get_keys(jwks_uri) do
          {:ok, jwks} ->
            # no filtering, there is no reason to have symmetric key returned here
            jwks

          {:error, _} ->
            []
        end

      _ ->
        raise "no jwks or jwks_uri field set in client configuration"
    end
  end

  @spec verify_jwt(
          String.t(),
          [JOSEUtils.JWK.t()],
          [JOSEUtils.JWA.sig_alg()]
        ) :: {:ok, %{required(String.t()) => any()}} | {:error, atom()}
  defp verify_jwt(client_assertion, jwks, allowed_algs) do
    case JOSEUtils.JWS.verify(client_assertion, jwks, allowed_algs) do
      {:ok, {payload, _key}} ->
        case Jason.decode(payload) do
          {:ok, claims} ->
            {:ok, claims}

          {:error, _} ->
            {:error, :invalid_jwt_payload}
        end

      :error ->
        {:error, :invalid_mac}
    end
  end

  @spec validate_claims(
          %{required(String.t()) => any()},
          server_metadata(),
          opts()
        ) :: :ok | {:error, atom()}
  defp validate_claims(claims, server_metadata, opts) do
    cond do
      claims["iss"] == nil ->
        {:error, :jwt_claims_missing_field_iss}

      claims["sub"] == nil ->
        {:error, :jwt_claims_missing_field_sub}

      claims["aud"] == nil ->
        {:error, :jwt_claims_missing_field_aud}

      claims["exp"] == nil ->
        {:error, :jwt_claims_missing_field_exp}

      claims["aud"] != server_metadata["token_endpoint"] ->
        {:error, :jwt_claims_invalid_audience}

      claims["exp"] < now() ->
        {:error, :jwt_claims_expired}

      claims["iat"] != nil and now() - claims["iat"] > opts[:iat_max_interval] ->
        {:error, :jwt_claims_iat_too_far_in_the_past}

      claims["nbf"] != nil and claims["nbf"] > now() ->
        {:error, :jwt_claims_nbf_in_the_future}

      opts[:protocol] == :oidc ->
        validate_claims_oidc(claims)

      true ->
        :ok
    end
  end

  @spec validate_claims_oidc(%{required(String.t()) => any()}) :: :ok | {:error, atom()}
  defp validate_claims_oidc(claims) do
    cond do
      claims["iss"] != claims["sub"] ->
        {:error, :jwt_claims_iss_sub_mismatch}

      claims["jti"] == nil ->
        {:error, :jwt_claims_missing_field_jti}

      true ->
        :ok
    end
  end

  @spec check_jwt_not_replayed(%{required(String.t()) => any()}, opts()) :: :ok | {:error, atom()}
  defp check_jwt_not_replayed(jwt_claims, opts) do
    # at this point:
    # - any JWT used within the OIDC protocol without jti has been rejected
    # - the :jti_register is necessarily set when used with OIDC
    if jwt_claims["jti"] && opts[:jti_register] do
      if opts[:jti_register].registered?(jwt_claims["jti"]) do
        {:error, :jwt_replayed}
      else
        :ok
      end
    else
      :ok
    end
  end

  @impl APIac.Authenticator
  def send_error_response(conn, error, opts) do
    error_response =
      case opts[:error_response_verbosity] do
        :debug ->
          %{"error" => "invalid_client", "error_description" => Exception.message(error)}

        :normal ->
          error_description =
            if error.reason == :credentials_not_found do
              "JWT credential not found in request"
            else
              "Invalid JWT credential"
            end

          %{"error" => "invalid_client", "error_description" => error_description}

        :minimal ->
          %{"error" => "invalid_client"}
      end

    conn
    |> Plug.Conn.put_resp_header("content-type", "application/json")
    |> Plug.Conn.send_resp(:unauthorized, Jason.encode!(error_response))
    |> Plug.Conn.halt()
  end

  @doc """
  Saves failure in a `Plug.Conn.t()`'s private field and returns the `conn`

  See the `APIac.AuthFailureResponseData` module for more information.
  """
  @spec save_authentication_failure_response(
          Plug.Conn.t(),
          %APIac.Authenticator.Unauthorized{},
          opts()
        ) :: Plug.Conn.t()
  def save_authentication_failure_response(conn, error, opts) do
    error_response =
      case opts[:error_response_verbosity] do
        :debug ->
          %{"error" => "invalid_client", "error_description" => Exception.message(error)}

        :normal ->
          error_description =
            if error.reason == :credentials_not_found do
              "JWT credential not found in request"
            else
              "Invalid JWT credential"
            end

          %{"error" => "invalid_client", "error_description" => error_description}

        :minimal ->
          %{"error" => "invalid_client"}
      end

    failure_response_data = %APIac.AuthFailureResponseData{
      module: __MODULE__,
      reason: error.reason,
      www_authenticate_header: nil,
      status_code: 400,
      body: Jason.encode!(error_response)
    }

    APIac.AuthFailureResponseData.put(conn, failure_response_data)
  end

  defp now(), do: System.system_time(:second)
end
