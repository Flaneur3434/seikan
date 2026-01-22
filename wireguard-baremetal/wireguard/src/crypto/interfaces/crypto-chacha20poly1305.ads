--  ChaCha20Poly1305 IETF (Authenticated Encryption with Associated Data)
--
--  Encrypts and provides integrity for messages
--  This is the public interface; implementations are platform-specific.
--
--  ZERO-COPY DESIGN (Design Contract Section F):
--    - Crypto consumes spans, not owned copies (F21)
--    - Plaintext destination is caller-provided (F22)
--    - Nonce and AAD are derived without copying (F23)
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

   ---------------------
   --  Zero-Copy Span API (Design Contract F21-F23)
   ---------------------

   --  Encrypts message from source span, writes ciphertext to destination span
   --
   --  ZERO-COPY: Reads plaintext directly from source span (RX buffer),
   --             writes ciphertext directly to destination span (TX buffer).
   --             AAD is read directly from span, no intermediate copies.
   --
   --  Ciphertext_Span must have capacity for plaintext + Tag_Bytes
   procedure Encrypt
     (Plaintext_Span  : Byte_Span;
      Ad_Span         : Byte_Span;
      Nonce           : Nonce_Buffer;
      Key             : Key_Buffer;
      -- The spans are (read-only descriptors) but the C FFI writes to the memory
      -- they point to
      Ciphertext_Span : Byte_Span; -- technically out parameter
      Result          : out Status)
   with
     Global => null,
     Pre    => Length (Ciphertext_Span) >= Length (Plaintext_Span) + Tag_Bytes;

   --  Decrypts ciphertext from source span, writes plaintext to dest span
   --
   --  ZERO-COPY: Reads ciphertext directly from source span (RX buffer),
   --             writes plaintext to destination span (TX/work buffer).
   --             AAD is read directly from span, no intermediate copies.
   --
   --  Plaintext_Span must have capacity for ciphertext - Tag_Bytes
   procedure Decrypt
     (Ciphertext_Span : Byte_Span;
      Ad_Span         : Byte_Span;
      Nonce           : Nonce_Buffer;
      Key             : Key_Buffer;
      -- The spans are (read-only descriptors) but the C FFI writes to the memory
      -- they point to
      Plaintext_Span  : Byte_Span; -- technically out parameter
      Result          : out Status)
   with
     Global => null,
     Pre    =>
       Length (Ciphertext_Span) >= Tag_Bytes
       and then
         Length (Plaintext_Span) >= Length (Ciphertext_Span) - Tag_Bytes;

end Crypto.ChaCha20Poly1305;
