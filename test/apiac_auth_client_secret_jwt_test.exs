defmodule APIacAuthClientJWTTest do
  use ExUnit.Case
  use Plug.Test

  alias APIacAuthClientJWT.Support.Callbacks

  @opts [
    client_callback: &Callbacks.client/1,
    jti_register: APIacAuthClientJWT.JTIRegister.ETS,
    server_metadata_callback: &Callbacks.server_metadata/0,
    error_response_verbosity: :debug
  ]

  @opts_rfc7523 @opts ++ [protocol: :rfc7523]

  @opts_oidc @opts ++ [protocol: :oidc]

  @assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

  describe "invalid options provided" do
    test "missing client callback" do
      assert_raise RuntimeError, ~r/missing.*client callback/, fn ->
        @opts_oidc
        |> Keyword.delete(:client_callback)
        |> APIacAuthClientJWT.init()
      end
    end

    test "missing server metadata callback" do
      assert_raise RuntimeError, ~r/missing.*server metadata callback/, fn ->
        @opts_oidc
        |> Keyword.delete(:server_metadata_callback)
        |> APIacAuthClientJWT.init()
      end
    end

    test "jti_register missing when OIDC is used" do
      assert_raise RuntimeError, ~r/missing.*replay protection/, fn ->
        @opts_oidc
        |> Keyword.delete(:jti_register)
        |> APIacAuthClientJWT.init()
      end
    end
  end

  describe "successful client authentication" do
    test "MACed JWT" do
      auth_req =
        %{
          client_assertion_type: @assertion_type,
          client_assertion: build_assertion("client1") |> mac("client1") |> IO.inspect()
        }

      opts = APIacAuthClientJWT.init(@opts)

      conn = conn(:post, "/", auth_req) |> APIacAuthClientJWT.call(opts)

      refute conn.status in 400..499
      refute conn.halted
      assert APIac.authenticated?(conn) == true
      assert APIac.machine_to_machine?(conn) == true
      assert APIac.authenticator(conn) == APIacAuthClientJWT
      assert APIac.client(conn) == "client1"
    end
  end

  defp build_assertion(client_id, replace_values \\ %{}) do
    %{
      iss: client_id,
      sub: client_id,
      aud: Callbacks.server_metadata()["token_endpoint"],
      exp: now() + 30,
      nbf: now(),
      iat: now(),
      jti: :crypto.strong_rand_bytes(12) |> Base.url_encode64(padding: false)
    }
    |> Map.merge(replace_values)
  end

  defp mac(jwt, client_id, alg \\ "HS256") do
    client_secret = Callbacks.client(client_id)["client_secret"]
    jwk = JOSE.JWK.from(%{"kty" => "oct", "k" => Base.encode64(client_secret)})
    message = jwt |> Jason.encode!()

    JOSE.JWS.sign(jwk, message, %{"alg" => alg})
    |> JOSE.JWS.compact()
    |> elem(1)
  end

  defp now(), do: System.system_time(:second)
end
