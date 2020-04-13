defmodule APIacAuthClientJWT.JTIRegister.ETS do
  @moduledoc """
  ETS implementation of `APIacAuthClientJWT.JTIRegister`

  This implementation is for test purpose, since it doesn't clean up `"jti"`s once they
  expire.

  The `:jti_register` ETS set table is meant to already exist when this module is used.
  """

  @table :jti_register

  @behaviour APIacAuthClientJWT.JTIRegister

  @impl true
  def register(jti, exp) do
    expires_in = exp - System.system_time(:second)

    expiration_time = System.monotonic_time(:second) + expires_in

    :ets.insert(@table, {jti, expiration_time})
  end

  @impl true
  def registered?(jti) do
    now_monotonic = System.monotonic_time(:second)

    case :ets.lookup(@table, jti) do
      [{_, expiration_time}] when expiration_time > now_monotonic ->
        true

      _ ->
        false
    end
  end
end
