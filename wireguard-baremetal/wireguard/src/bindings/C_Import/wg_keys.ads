--  WG_Keys - Ada interface to sdkconfig-based WireGuard key storage
--
--  Thin import of C functions from wg_keys.c that decode hex keys
--  from ESP-IDF's sdkconfig.h into raw byte arrays.
--
--  The C functions have signature: bool wg_get_*(uint8_t out[32])
--  Ada imports them as functions returning C_bool with a System.Address
--  parameter (the out array decays to a pointer in C).
--
--  Usage:
--    Key : Crypto.KX.Secret_Key;
--    if WG_Keys.Get_Static_Private_Key (Key) then
--       --  Key loaded successfully
--    end if;

with Interfaces.C;
with Crypto.KX;

package WG_Keys
  with SPARK_Mode => Off
is

   --  Load the ESP32 static private key from CONFIG_WG_STATIC_PRIVATE_KEY.
   --  Returns True on success, False if not configured or invalid hex.
   function Get_Static_Private_Key
     (Key : out Crypto.KX.Secret_Key) return Interfaces.C.C_bool
   with Import, Convention => C, External_Name => "wg_get_static_private_key";

   --  Load the peer's public key from CONFIG_WG_PEER_PUBLIC_KEY.
   function Get_Peer_Public_Key
     (Key : out Crypto.KX.Public_Key) return Interfaces.C.C_bool
   with Import, Convention => C, External_Name => "wg_get_peer_public_key";

   --  Load the optional pre-shared key from CONFIG_WG_PRESHARED_KEY.
   --  Returns False if empty/unset (Key will be all zeros).
   function Get_Preshared_Key
     (Key : out Crypto.KX.Secret_Key) return Interfaces.C.C_bool
   with Import, Convention => C, External_Name => "wg_get_preshared_key";

end WG_Keys;
