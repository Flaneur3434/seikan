--  ChaCha20Poly1305 IETF (Authenticated Encryption with Associated Data)
--
--  Encrypts and provides integrity for messages
--  This is the public interface; implementations are platform-specific.

with Interfaces;

package Crypto.ChaCha20Poly1305
  with SPARK_Mode => On
is
   use Interfaces;

   --  IETF ChaCha20-Poly1305 AEAD Constants
   Key_Bytes   : constant Positive := 32;  --  256-bit key
   Nonce_Bytes : constant Positive := 12;  --  96-bit nonce (IETF variant)
   Tag_Bytes   : constant Positive := 16;  --  128-bit authentication tag

   --  ChaCha20Poly1305 Types
   type Nonce is array (0 .. Nonce_Bytes - 1) of Unsigned_8;
   type Key is array (0 .. Key_Bytes - 1) of Unsigned_8;

   type Context is record
      N : Nonce;  --  96-bit nonce
      K : Key;    --  256-bit key
   end record;

   --  Encrypts message and appends authentication tag
   --  Ciphertext must be Plaintext'Length + Tag_Bytes
   procedure Encrypt
     (Plaintext  : Byte_Array;
      Ad         : Byte_Array;
      Ctx        : Context;
      Ciphertext : out Byte_Array;
      Result     : out Crypto.Status)
   with
     Global => null,
     Pre    => Ciphertext'Length = Plaintext'Length + Tag_Bytes;

   --  Verifies tag and decrypts ciphertext
   --  Plaintext must be Ciphertext'Length - Tag_Bytes
   procedure Decrypt
     (Ciphertext : Byte_Array;
      Ad         : Byte_Array;
      Ctx        : Context;
      Plaintext  : out Byte_Array;
      Result     : out Crypto.Status)
   with
     Global => null,
     Pre    => Ciphertext'Length >= Tag_Bytes
               and then Plaintext'Length = Ciphertext'Length - Tag_Bytes;

end Crypto.ChaCha20Poly1305;
