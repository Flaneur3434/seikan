--  ChaCha20Poly1305 IETF (Authenticated Encryption with Associated Data)
--
--  Encrypts and provides integrity for messages
--  This is the public interface; implementations are platform-specific.
--
--  ZERO-COPY DESIGN
--    - Crypto consumes spans, not owned copies
--    - Plaintext destination is caller-provided
--    - Nonce and AAD are derived without copying
--    - All span-based APIs read directly from RX buffers
--    - All span-based APIs write directly to TX buffers

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
   subtype Nonce_Buffer is Byte_Array (0 .. Nonce_Bytes - 1);
   subtype Key_Buffer is Byte_Array (0 .. Key_Bytes - 1);

   --  Encrypts message from source span, writes ciphertext to destination span
   procedure Encrypt
     (Plaintext_Span  : Byte_Span;
      Ad_Span         : Byte_Span;
      Nonce           : Nonce_Buffer;
      Key             : Key_Buffer;
      --  The spans are (read-only descriptors) but the C FFI writes to the
      --  memory they point to. So it's technically an out parameter.
      Ciphertext_Span : Byte_Span;
      Result          : out Status)
   with
     Global => null,
     Pre    =>
       Length (Ciphertext_Span) >= Tag_Bytes
       and then
         Length (Ciphertext_Span) - Tag_Bytes >= Length (Plaintext_Span);

   --  Decrypts ciphertext from source span, writes plaintext to dest span
   procedure Decrypt
     (Ciphertext_Span : Byte_Span;
      Ad_Span         : Byte_Span;
      Nonce           : Nonce_Buffer;
      Key             : Key_Buffer;
      --  The spans are (read-only descriptors) but the C FFI writes to the
      --  memory they point to. So it's technically an out parameter.
      Plaintext_Span  : Byte_Span;
      Result          : out Status)
   with
     Global => null,
     Pre    =>
       Length (Ciphertext_Span) >= Tag_Bytes
       and then
         Length (Plaintext_Span) >= Length (Ciphertext_Span) - Tag_Bytes;

   procedure Build_Nonce (Counter : Unsigned_64; N : out Nonce_Buffer)
   with Post => (for all I in 0 .. 3 => N (I) = 0);

end Crypto.ChaCha20Poly1305;
