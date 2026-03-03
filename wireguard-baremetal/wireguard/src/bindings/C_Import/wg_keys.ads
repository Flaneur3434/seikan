--  WG_Keys - Ada interface to sdkconfig-based WireGuard key storage
--
--  Thin import of C functions from wg_keys.c that decode hex keys
--  from ESP-IDF's sdkconfig.h into raw byte arrays, plus per-peer
--  AllowedIPs/keepalive configuration getters.
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

   --  ── Key loading ────────────────────────────────────────────────

   --  Load the ESP32 static private key from CONFIG_WG_STATIC_PRIVATE_KEY.
   --  Returns True on success, False if not configured or invalid hex.
   function Get_Static_Private_Key
     (Key : out Crypto.KX.Secret_Key) return Interfaces.C.C_bool
   with Import, Convention => C, External_Name => "wg_get_static_private_key";

   --  Load peer 1's public key from CONFIG_WG_PEER_PUBLIC_KEY.
   function Get_Peer_Public_Key
     (Key : out Crypto.KX.Public_Key) return Interfaces.C.C_bool
   with Import, Convention => C, External_Name => "wg_get_peer_public_key";

   --  Load peer 1's optional pre-shared key from CONFIG_WG_PRESHARED_KEY.
   --  Returns False if empty/unset (Key will be all zeros).
   function Get_Preshared_Key
     (Key : out Crypto.KX.Secret_Key) return Interfaces.C.C_bool
   with Import, Convention => C, External_Name => "wg_get_preshared_key";

   --  Load peer 2's public key from CONFIG_WG_PEER2_PUBLIC_KEY.
   --  Returns False if not configured or empty.
   function Get_Peer2_Public_Key
     (Key : out Crypto.KX.Public_Key) return Interfaces.C.C_bool
   with Import, Convention => C, External_Name => "wg_get_peer2_public_key";

   --  Load peer 2's optional pre-shared key.
   function Get_Peer2_Preshared_Key
     (Key : out Crypto.KX.Secret_Key) return Interfaces.C.C_bool
   with Import, Convention => C, External_Name => "wg_get_peer2_preshared_key";

   --  ── Per-peer configuration ─────────────────────────────────────

   --  Get peer's AllowedIP address (host byte order, 0 = 0.0.0.0).
   function Get_Peer_Allowed_IP
     (Peer : Interfaces.C.unsigned) return Interfaces.C.unsigned
   with Import, Convention => C, External_Name => "wg_get_peer_allowed_ip";

   --  Get peer's AllowedIP prefix length (0..32).
   function Get_Peer_Allowed_Prefix
     (Peer : Interfaces.C.unsigned) return Interfaces.C.unsigned_char
   with Import, Convention => C, External_Name => "wg_get_peer_allowed_prefix";

   --  Get peer's persistent keepalive interval in seconds (0 = disabled).
   function Get_Peer_Keepalive
     (Peer : Interfaces.C.unsigned) return Interfaces.C.unsigned_short
   with Import, Convention => C, External_Name => "wg_get_peer_keepalive";

end WG_Keys;
