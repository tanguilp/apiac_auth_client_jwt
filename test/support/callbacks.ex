defmodule APIacAuthClientJWT.Support.Callbacks do
  def client("client1") do
    %{
      "token_endpoint_auth_method" => "client_secret_jwt",
      "client_secret" => "client 1's secret is of 32 chars"
    }
  end

  def client("client2") do
    %{
      "token_endpoint_auth_method" => "private_key_jwt",
      "jwks" => %{
        "keys" => [
          %{
            "use" => "sig",
            "crv" => "P-256",
            "d" => "-0DZQ6jsptawoGnDKoBLV_RWkL0hMFSObVOT1Hcm7rg",
            "kty" => "EC",
            "x" => "ZLMq7qopVjulV_ybhTWO83VRZrT78Mz3ZOpyEDUB3d0",
            "y" => "Au0khh00q3q04n90MIojF1KZrbxmFTsxGBFvE3SgHeU"
          }
        ]
      }
    }
  end

  def client("client3") do
    %{
      "token_endpoint_auth_method" => "client_secret_jwt",
      "client_secret" => "client 3's secret",
      "jwks" => %{
        "keys" => [
          %{
            "crv" => "P-256",
            "d" => "4NQaM2vcBj5so8Bk5NZAJl8k3GXuyjVgCHlf7r1QrQI",
            "kty" => "EC",
            "x" => "uRmudlbKWU9REopZxz_jXD-YMfwxAMVlL5XPd6Z3_bE",
            "y" => "R40rPUIgu3zR6kumRsUEc2LclE0cME8jgXI2yGxIFA8"
          }
        ]
      }
    }
  end

  def server_metadata() do
    %{
      "token_endpoint" => "https://example.org/auth/oidc/token",
      "token_endpoint_auth_signing_alg_values_supported" => ["HS256", "HS512", "ES256"]
    }
  end
end
