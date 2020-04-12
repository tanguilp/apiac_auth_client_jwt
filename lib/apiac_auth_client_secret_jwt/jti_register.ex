defmodule APIacAuthClientJWT.JTIRegister do
  @moduledoc """
  Behaviour for modules implementing JTI registration, to prevent JWT replay

  To avoid allowing use of a JWT in case the server's time changes backward, an implementation
  *should* use monotonic time (see `System.monotonic_time/1`).
  """

  @doc """
  Registers a `"jti"` with its expiration date `"exp"`
  """
  @callback register(jti :: String.t(), exp :: non_neg_integer()) :: any()

  @doc """
  Returns `true` if a `"jti"` is registered and not expired, `false` otherwise
  """
  @callback registered?(jti :: String.t()) :: boolean()
end
