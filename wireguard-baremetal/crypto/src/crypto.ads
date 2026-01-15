with Interfaces;

package Crypto
  with SPARK_Mode => On
is
   ---------------------
   --  Protocol Constants
   ---------------------

   --  X25519
   Scalarmult_Bytes        : constant := 32;
   Scalarmult_Scalar_Bytes : constant := 32;

   --  IETF ChaCha20-Poly1305 AEAD
   AEAD_Key_Bytes   : constant := 32;
   AEAD_Nonce_Bytes : constant := 12;
   AEAD_Tag_Bytes   : constant := 16;

   --  BLAKE2b
   Hash_Bytes     : constant := 32;
   Hash_Key_Bytes : constant := 32;

   ---------------------
   --  Public Types
   ---------------------

   subtype Unsigned_8 is Interfaces.Unsigned_8;
   type Byte_Array is array (Natural range <>) of Unsigned_8;

   type X25519_Public_Key is array (0 .. Scalarmult_Bytes - 1) of Unsigned_8;
   type X25519_Secret_Key is
     array (0 .. Scalarmult_Scalar_Bytes - 1) of Unsigned_8;
   type X25519_Shared_Secret is
     array (0 .. Scalarmult_Bytes - 1) of Unsigned_8;

   type Key_Pair is record
      Public_Key : X25519_Public_Key;
      Secret_Key : X25519_Secret_Key;
   end record;

   type ChaCha20Poly1305_Nonce is array (0 .. AEAD_Nonce_Bytes - 1) of Unsigned_8;
   type ChaCha20Poly1305_Key is array (0 .. AEAD_Key_Bytes - 1) of Unsigned_8;

   type Status is (Success, Error_Failed, Error_Invalid_Argument);
   function Is_Success (S : Status) return Boolean
   is (S = Success);

end Crypto;
