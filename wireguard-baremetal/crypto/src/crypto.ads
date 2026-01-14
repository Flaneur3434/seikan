with Interfaces;

package Crypto
  with SPARK_Mode => On
is
   subtype Unsigned_8 is Interfaces.Unsigned_8;
   type Byte_Array is array (Natural range <>) of Unsigned_8;

   type Status is (Success, Error_Failed, Error_Invalid_Argument);
   function Is_Success (S : Status) return Boolean is (S = Success);

   -- LibSodium Constants

   -- X25519 / crypto_scalarmult
   Scalarmult_Bytes        : constant := 32; -- crypto_scalarmult_BYTES
   Scalarmult_Scalar_Bytes : constant := 32; -- crypto_scalarmult_SCALARBYTES

   -- crypto_box (uses X25519 + XSalsa20-Poly1305)
   Box_Public_Key_Bytes : constant := 32; -- crypto_box_PUBLICKEYBYTES
   Box_Secret_Key_Bytes : constant := 32; -- crypto_box_SECRETKEYBYTES
   Box_Nonce_Bytes      : constant := 24; -- crypto_box_NONCEBYTES
   Box_Mac_Bytes        : constant := 16; -- crypto_box_MACBYTES

   -- ChaCha20-Poly1305 AEAD
   AEAD_Key_Bytes   : constant := 32;  -- crypto_aead_chacha20poly1305_KEYBYTES
   AEAD_Nonce_Bytes : constant := 12;  -- crypto_aead_chacha20poly1305_ietf_NPUBBYTES
   AEAD_Tag_Bytes   : constant := 16;  -- crypto_aead_chacha20poly1305_ABYTES

   -- BLAKE2b (libsodium's generic hash)
   Hash_Bytes     : constant := 32;  -- crypto_generichash_BYTES
   Hash_Key_Bytes : constant := 32;  -- crypto_generichash_KEYBYTES

   type X25519_Public_Key is array (0 .. Scalarmult_Bytes - 1) of Unsigned_8;
   type X25519_Secret_Key is array (0 .. Scalarmult_Scalar_Bytes - 1) of Unsigned_8;
   type X25519_Shared_Secret is array (0 .. Scalarmult_Bytes - 1) of Unsigned_8;

   type Key_Pair is record
      Public_Key : X25519_Public_Key;
      Secret_Key : X25519_Secret_Key;
   end record;

end Crypto;
