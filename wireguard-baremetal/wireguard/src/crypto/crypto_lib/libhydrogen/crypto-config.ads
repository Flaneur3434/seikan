--  Crypto.Config - Public Crypto Configuration Constants
--
--  This package exposes the platform-specific crypto constants to the
--  public interface. It acts as a bridge between the private Crypto.Platform
--  package and the public Crypto.* interfaces.
--
--  The constants here are derived from libhydrogen.
--  
--  libhydrogen: Gimli-based KX, Secretbox, Hash

package Crypto.Config
  with SPARK_Mode => On
is
   --  Key Exchange constants (hydro_kx_*)
   KX_Public_Key_Bytes  : constant Positive := 32;  --  hydro_kx_PUBLICKEYBYTES
   KX_Secret_Key_Bytes  : constant Positive := 32;  --  hydro_kx_SECRETKEYBYTES
   KX_Shared_Key_Bytes  : constant Positive := 32;  --  hydro_kx_SESSIONKEYBYTES

   --  AEAD constants (hydro_secretbox_*)
   AEAD_Key_Bytes   : constant Positive := 32;  --  hydro_secretbox_KEYBYTES
   AEAD_Nonce_Bytes : constant Natural  := 0;   --  libhydrogen uses internal msg_id
   AEAD_Tag_Bytes   : constant Positive := 36;  --  hydro_secretbox_HEADERBYTES (20+16)

   --  NOTE: Hashing uses Crypto.Blake2 directly (BLAKE2s is part of
   --  the WireGuard/VeriGuard protocol, independent of crypto backend).

end Crypto.Config;
