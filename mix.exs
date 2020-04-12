defmodule APIacAuthClientJWT.MixProject do
  use Mix.Project

  def project do
    [
      app: :apiac_auth_client_jwt,
      version: "0.1.0",
      elixir: "~> 1.9",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:apiac, github: "tanguilp/apiac", tag: "0.3.0"},
      {:dialyxir, "~> 1.0", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.21", only: :dev, runtime: false},
      {:jose_utils, github: "tanguilp/jose_utils", tag: "v0.1.0"},
      {:jwks_uri_updater, github: "tanguilp/jwks_uri_updater", tag: "v0.2.0"}
    ]
  end
end
