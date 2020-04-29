defmodule APIacAuthClientJWT.MixProject do
  use Mix.Project

  def project do
    [
      app: :apiac_auth_client_jwt,
      description: "APIac Elixir plug that implements RFC7523 client JWT authentication",
      elixirc_paths: elixirc_paths(Mix.env()),
      version: "1.0.0",
      elixir: "~> 1.9",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      docs: [main: "readme", extras: ["README.md"]],
      package: package(),
      source_url: "https://github.com/tanguilp/apiac_auth_client_jwt"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:apiac, "~> 1.0"},
      {:dialyxir, "~> 1.0", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.21", only: :dev, runtime: false},
      {:jose_utils, "~> 0.1.0"},
      {:jwks_uri_updater, "~> 1.0"}
    ]
  end

  def package() do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/tanguilp/apiac_auth_client_jwt"}
    ]
  end
end
