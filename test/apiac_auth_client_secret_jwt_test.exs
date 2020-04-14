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
          client_assertion: build_assertion("client1") |> mac("client1")
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

    test "signed JWT" do
      auth_req =
        %{
          client_assertion_type: @assertion_type,
          client_assertion: build_assertion("client2") |> sign("client2")
        }

      opts = APIacAuthClientJWT.init(@opts)

      conn = conn(:post, "/", auth_req) |> APIacAuthClientJWT.call(opts)

      refute conn.status in 400..499
      refute conn.halted
      assert APIac.authenticated?(conn) == true
      assert APIac.machine_to_machine?(conn) == true
      assert APIac.authenticator(conn) == APIacAuthClientJWT
      assert APIac.client(conn) == "client2"
    end

    test "claims are forwared" do
      auth_req =
        %{
          client_assertion_type: @assertion_type,
          client_assertion: build_assertion("client1", %{"claim_1" => 42}) |> mac("client1")
        }

      opts = APIacAuthClientJWT.init(@opts)

      conn = conn(:post, "/", auth_req) |> APIacAuthClientJWT.call(opts)

      assert APIac.metadata(conn)["claim_1"] == 42
    end
  end

  describe "invalid assertion" do
    test "missing" do
      auth_req =
        %{
          client_assertion_type: @assertion_type
        }

      opts = APIacAuthClientJWT.init(@opts_oidc)

      conn = conn(:post, "/", auth_req) |> APIacAuthClientJWT.call(opts)
      resp = conn.resp_body |> Jason.decode!()

      assert conn.status == 400
      assert resp["error"] == "invalid_client"
      assert resp["error_description"] =~ ~r/credential.*not.*found/
    end

    test "malformed" do
      auth_req =
        %{
          client_assertion_type: @assertion_type,
          client_assertion: "a.b.c.d"
        }

      opts = APIacAuthClientJWT.init(@opts_oidc)

      conn = conn(:post, "/", auth_req) |> APIacAuthClientJWT.call(opts)
      resp = conn.resp_body |> Jason.decode!()

      assert conn.status == 400
      assert resp["error"] == "invalid_client"
      assert resp["error_description"] =~ ~r/invalid.*jwt/
    end

    test "invalid MAC" do
      auth_req =
        %{
          client_assertion_type: @assertion_type,
          client_assertion: build_assertion("client1") |> mac("client3")
        }

      opts = APIacAuthClientJWT.init(@opts_oidc)

      conn = conn(:post, "/", auth_req) |> APIacAuthClientJWT.call(opts)
      resp = conn.resp_body |> Jason.decode!()

      assert conn.status == 400
      assert resp["error"] == "invalid_client"
      assert resp["error_description"] =~ ~r/invalid.*mac/
    end

    test "invalid signature" do
      auth_req =
        %{
          client_assertion_type: @assertion_type,
          client_assertion: build_assertion("client2") |> sign("client3")
        }

      opts = APIacAuthClientJWT.init(@opts_oidc)

      conn = conn(:post, "/", auth_req) |> APIacAuthClientJWT.call(opts)
      resp = conn.resp_body |> Jason.decode!()

      assert conn.status == 400
      assert resp["error"] == "invalid_client"
      assert resp["error_description"] =~ ~r/invalid.*sig/
    end
  end

  describe "errors: invalid or missing claims" do
    test "missing iss claim" do
      auth_req =
        %{
          client_assertion_type: @assertion_type,
          client_assertion: build_assertion("client1") |> Map.delete(:iss) |> mac("client1")
        }

      opts = APIacAuthClientJWT.init(@opts_oidc)

      conn = conn(:post, "/", auth_req) |> APIacAuthClientJWT.call(opts)
      resp = conn.resp_body |> Jason.decode!()

      assert conn.status == 400
      assert resp["error"] == "invalid_client"
      assert resp["error_description"] =~ ~r/missing.*iss/
    end

    test "missing sub claim" do
      auth_req =
        %{
          client_assertion_type: @assertion_type,
          client_assertion: build_assertion("client1") |> Map.delete(:sub) |> mac("client1")
        }

      opts = APIacAuthClientJWT.init(@opts_oidc)

      conn = conn(:post, "/", auth_req) |> APIacAuthClientJWT.call(opts)
      resp = conn.resp_body |> Jason.decode!()

      assert conn.status == 400
      assert resp["error"] == "invalid_client"
      assert resp["error_description"] =~ ~r/missing.*sub/
    end

    test "missing aud claim" do
      auth_req =
        %{
          client_assertion_type: @assertion_type,
          client_assertion: build_assertion("client1") |> Map.delete(:aud) |> mac("client1")
        }

      opts = APIacAuthClientJWT.init(@opts_oidc)

      conn = conn(:post, "/", auth_req) |> APIacAuthClientJWT.call(opts)
      resp = conn.resp_body |> Jason.decode!()

      assert conn.status == 400
      assert resp["error"] == "invalid_client"
      assert resp["error_description"] =~ ~r/missing.*aud/
    end

    test "missing jti claim when OIDC is used" do
      auth_req =
        %{
          client_assertion_type: @assertion_type,
          client_assertion: build_assertion("client1") |> Map.delete(:jti) |> mac("client1")
        }

      opts = APIacAuthClientJWT.init(@opts_oidc)

      conn = conn(:post, "/", auth_req) |> APIacAuthClientJWT.call(opts)
      resp = conn.resp_body |> Jason.decode!()

      assert conn.status == 400
      assert resp["error"] == "invalid_client"
      assert resp["error_description"] =~ ~r/missing.*jti/
    end

    test "OIDC: iss is not set to the client id" do
      auth_req =
        %{
          client_assertion_type: @assertion_type,
          client_assertion: build_assertion("client1", %{iss: "client99"}) |> mac("client1")
        }

      opts = APIacAuthClientJWT.init(@opts_oidc)

      conn = conn(:post, "/", auth_req) |> APIacAuthClientJWT.call(opts)
      resp = conn.resp_body |> Jason.decode!()

      assert conn.status == 400
      assert resp["error"] == "invalid_client"
      assert resp["error_description"] =~ ~r/iss.*sub.*mismatch/
    end

    test "client id in assertion and body differ" do
      auth_req =
        %{
          client_assertion_type: @assertion_type,
          client_assertion: build_assertion("client1") |> mac("client1"),
          client_id: "client2"
        }

      opts = APIacAuthClientJWT.init(@opts_oidc)

      conn = conn(:post, "/", auth_req) |> APIacAuthClientJWT.call(opts)
      resp = conn.resp_body |> Jason.decode!()

      assert conn.status == 400
      assert resp["error"] == "invalid_client"
      assert resp["error_description"] =~ ~r/client.*id.*iss.*mismatch/
    end

    test "audience is incorrect" do
      auth_req =
        %{
          client_assertion_type: @assertion_type,
          client_assertion: build_assertion("client1", %{aud: "incorrect"}) |> mac("client1")
        }

      opts = APIacAuthClientJWT.init(@opts_oidc)

      conn = conn(:post, "/", auth_req) |> APIacAuthClientJWT.call(opts)
      resp = conn.resp_body |> Jason.decode!()

      assert conn.status == 400
      assert resp["error"] == "invalid_client"
      assert resp["error_description"] =~ ~r/invalid.*aud/
    end

    test "exp is in the past" do
      auth_req =
        %{
          client_assertion_type: @assertion_type,
          client_assertion: build_assertion("client1", %{exp: now() - 1}) |> mac("client1")
        }

      opts = APIacAuthClientJWT.init(@opts_oidc)

      conn = conn(:post, "/", auth_req) |> APIacAuthClientJWT.call(opts)
      resp = conn.resp_body |> Jason.decode!()

      assert conn.status == 400
      assert resp["error"] == "invalid_client"
      assert resp["error_description"] =~ ~r/expired/
    end

    test "nbf is in the future" do
      auth_req =
        %{
          client_assertion_type: @assertion_type,
          client_assertion: build_assertion("client1", %{nbf: now() + 1}) |> mac("client1")
        }

      opts = APIacAuthClientJWT.init(@opts_oidc)

      conn = conn(:post, "/", auth_req) |> APIacAuthClientJWT.call(opts)
      resp = conn.resp_body |> Jason.decode!()

      assert conn.status == 400
      assert resp["error"] == "invalid_client"
      assert resp["error_description"] =~ ~r/nbf.*future/
    end

    test "iat is in too far in the past" do
      auth_req =
        %{
          client_assertion_type: @assertion_type,
          client_assertion: build_assertion("client1", %{iat: now() - 60}) |> mac("client1")
        }

      opts = APIacAuthClientJWT.init(@opts_oidc)

      conn = conn(:post, "/", auth_req) |> APIacAuthClientJWT.call(opts)
      resp = conn.resp_body |> Jason.decode!()

      assert conn.status == 400
      assert resp["error"] == "invalid_client"
      assert resp["error_description"] =~ ~r/iat.*past/
    end
  end

  describe "jti claim" do
    test "JWT used twice is rejected" do
      auth_req =
        %{
          client_assertion_type: @assertion_type,
          client_assertion: build_assertion("client1") |> mac("client1")
        }

      opts = APIacAuthClientJWT.init(@opts)

      conn(:post, "/", auth_req) |> APIacAuthClientJWT.call(opts)

      conn = conn(:post, "/", auth_req) |> APIacAuthClientJWT.call(opts)
      resp = conn.resp_body |> Jason.decode!()

      assert conn.status == 400
      assert resp["error"] == "invalid_client"
      assert resp["error_description"] =~ ~r/replayed/
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

  defp sign(jwt, client_id, alg \\ "ES256") do
    jwk = Callbacks.client(client_id)["jwks"]["keys"] |> JOSEUtils.JWKS.signature_keys("ES256")
    message = jwt |> Jason.encode!()

    JOSE.JWS.sign(jwk, message, %{"alg" => alg})
    |> JOSE.JWS.compact()
    |> elem(1)
    |> List.first()
  end

  defp now(), do: System.system_time(:second)
end
