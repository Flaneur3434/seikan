--  XChaCha20-Poly1305 AEAD (24-byte nonce)
--
--  Used exclusively by the WireGuard cookie mechanism (§5.4.7).
--  Cookie replies encrypt a 16-byte cookie using XChaCha20-Poly1305
--  with the MAC1 field of the triggering message as additional data.
--
--  Key = HASH("cookie--" || Spub_r)  (32 bytes)
--  Nonce = random 24 bytes
--  Plaintext = Mac(Rm, source_ip_port)  (16 bytes)

with Utils; use Utils;

package Crypto.XAEAD
  with SPARK_Mode => On,
       Always_Terminates
is
   Key_Bytes   : constant := 32;
   Nonce_Bytes : constant := 24;
   Tag_Bytes   : constant := 16;

   --  Cookie-specific sizes (§5.4.7)
   Cookie_Bytes           : constant := 16;  --  Mac(Rm, source_ip_port)
   Encrypted_Cookie_Bytes : constant := Cookie_Bytes + Tag_Bytes;  --  32
   Mac1_Bytes             : constant := 16;  --  AD for cookie encryption

   subtype Key_Buffer   is Byte_Array (0 .. Key_Bytes - 1);
   subtype Nonce_Buffer is Byte_Array (0 .. Nonce_Bytes - 1);

   --  Encrypt a cookie with XChaCha20-Poly1305.
   --  Plaintext is the 16-byte cookie, AD is the 16-byte MAC1.
   procedure Encrypt
     (Plaintext  : Byte_Array;
      Ad         : Byte_Array;
      Nonce      : Nonce_Buffer;
      Key        : Key_Buffer;
      Ciphertext : out Byte_Array;
      Result     : out Status)
   with
     Global => null,
     Pre    =>
       Plaintext'Length = Cookie_Bytes
       and then Ad'Length = Mac1_Bytes
       and then Ciphertext'Length = Encrypted_Cookie_Bytes;

   --  Decrypt a cookie with XChaCha20-Poly1305.
   --  Ciphertext is the 32-byte encrypted cookie, AD is the 16-byte MAC1.
   procedure Decrypt
     (Ciphertext : Byte_Array;
      Ad         : Byte_Array;
      Nonce      : Nonce_Buffer;
      Key        : Key_Buffer;
      Plaintext  : out Byte_Array;
      Result     : out Status)
   with
     Global => null,
     Pre    =>
       Ciphertext'Length = Encrypted_Cookie_Bytes
       and then Ad'Length = Mac1_Bytes
       and then Plaintext'Length = Cookie_Bytes;

end Crypto.XAEAD;
