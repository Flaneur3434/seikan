--  ChaCha20Poly1305 IETF (Authenticated Encryption with Associated Data)
--
--  Encrypts and provides integrity for messages
--  This is the public interface; implementations are platform-specific.

package Crypto.ChaCha20Poly1305
  with SPARK_Mode => On
is
   use type Unsigned_8;  --  Make parent package type operators useable

   --  Encrypts message and concatenates it with authentication tag
   procedure Encrypt
     (Plaintext  : Byte_Array;
      Ad         : Byte_Array;
      Nonce      : ChaCha20Poly1305_Nonce;
      Key        : ChaCha20Poly1305_Key;
      Ciphertext : out Byte_Array;
      Result     : out Crypto.Status)
   with
     Pre    => Ciphertext'Length = Plaintext'Length + AEAD_Tag_Bytes,
     Post   => (if Result = Crypto.Success then Ciphertext'Initialized),
     Global => null;

   -- Verifies that the cipher text includes valid tag and returns decrypted message
   procedure Decrypt
     (Ciphertext : Byte_Array;
      Ad         : Byte_Array;
      Nonce      : ChaCha20Poly1305_Nonce;
      Key        : ChaCha20Poly1305_Key;
      Plaintext  : out Byte_Array;
      Result     : out Crypto.Status)
   with
     Pre    =>
       Ciphertext'Length >= AEAD_Tag_Bytes
       and then Plaintext'Length = Ciphertext'Length - AEAD_Tag_Bytes,
     Post   =>
       (if Result /= Crypto.Success
        then (for all I in Plaintext'Range => Plaintext (I) = 0)),
     Global => null;

end Crypto.ChaCha20Poly1305;
