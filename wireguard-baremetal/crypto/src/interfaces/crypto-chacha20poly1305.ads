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

   --  Encrypts message and concatenates it with authentication tag
   procedure Encrypt
     (Plaintext  : Byte_Array;
      Ad         : Byte_Array;
      N          : Nonce;
      K          : Key;
      Ciphertext : out Byte_Array;
      Result     : out Crypto.Status)
   with
     Pre    => Ciphertext'Length = Plaintext'Length + Tag_Bytes,
     Global => null;

   --  Verifies that the cipher text includes valid tag and returns decrypted
   procedure Decrypt
     (Ciphertext : Byte_Array;
      Ad         : Byte_Array;
      N          : Nonce;
      K          : Key;
      Plaintext  : out Byte_Array;
      Result     : out Crypto.Status)
   with
     Pre    =>
       Ciphertext'Length >= Tag_Bytes
       and then Plaintext'Length = Ciphertext'Length - Tag_Bytes,
     Post   =>
       (if Result /= Crypto.Success
        then (for all I in Plaintext'Range => Plaintext (I) = 0)),
     Global => null;

end Crypto.ChaCha20Poly1305;
