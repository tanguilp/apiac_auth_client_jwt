defmodule APIacAuthClientJWT.Support.Callbacks do
  def client("client1") do
    %{
      "token_endpoint_auth_method" => "client_secret_jwt",
      "client_secret" => "client 1's secret"
    }
  end

  def server_metadata() do
    %{
      "token_endpoint" => "https://example.org/auth/oidc/token",
      "token_endpoint_auth_signing_alg_values_supported" => ["HS256", "HS512"]
    }
  end
end
