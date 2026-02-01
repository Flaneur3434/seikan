--  Crypto.Config - Public Crypto Configuration Constants
--
--  This package exposes the platform-specific crypto constants to the
--  public interface. It acts as a bridge between the private Crypto.Platform
--  package and the public Crypto.* interfaces.
--
--  The constants here are derived from the selected crypto backend.
--  - libsodium: X25519, ChaCha20-Poly1305 IETF, BLAKE2s
--  - libhydrogen: Gimli-based KX, Secretbox, Hash

package Crypto.Config
  with SPARK_Mode => On
is
   --  Key Exchange constants
   KX_Public_Key_Bytes  : constant Positive := 32;
   KX_Secret_Key_Bytes  : constant Positive := 32;
   KX_Shared_Key_Bytes  : constant Positive := 32;

   --  AEAD constants (ChaCha20-Poly1305 IETF)
   AEAD_Key_Bytes   : constant Positive := 32;
   AEAD_Nonce_Bytes : constant Natural  := 12;
   AEAD_Tag_Bytes   : constant Positive := 16;

   --  NOTE: Hashing uses Crypto.Blake2 directly (BLAKE2s is part of
   --  the WireGuard protocol, independent of crypto backend).

end Crypto.Config;
