--  ChaCha20Poly1305 IETF (Authenticated Encryption with Associated Data)
--
--  Encrypts and provides integrity for messages
--  This is the public interface; implementations are platform-specific.
--
--  ZERO-COPY DESIGN
--    - Uses native Ada arrays (passed by reference automatically)
--    - In-place encryption overwrites plaintext with ciphertext
--    - No custom span types needed - Ada's type system enforces safety
--
--  IN-PLACE ENCRYPTION (for TX path)
--    Buffer layout before encryption:
--      [0..15]                    = Transport header (AAD)
--      [16..16+PT_len-1]          = Plaintext payload
--      [16+PT_len..16+PT_len+15]  = Reserved for Poly1305 tag
--
--    After encryption:
--      [0..15]                    = Transport header (unchanged)
--      [16..16+PT_len-1]          = Ciphertext (overwrites plaintext)
--      [16+PT_len..16+PT_len+15]  = Authentication tag

with Interfaces;
with Utils; use Utils;

package Crypto.ChaCha20Poly1305
  with SPARK_Mode => On
is
   use Interfaces;

   --  IETF ChaCha20-Poly1305 AEAD Constants
   Key_Bytes   : constant Positive := 32;  --  256-bit key
   Nonce_Bytes : constant Positive := 12;  --  96-bit nonce (IETF variant)
   Tag_Bytes   : constant Positive := 16;  --  128-bit authentication tag

   --  WireGuard Transport Header size
   Header_Bytes : constant Positive := 16;

   --  Maximum buffer size for precondition proofs
   Max_Buffer_Size : constant := Utils.Max_Packet_Size;

   --  ChaCha20Poly1305 Types
   subtype Nonce_Buffer is Byte_Array (0 .. Nonce_Bytes - 1);
   subtype Key_Buffer is Byte_Array (0 .. Key_Bytes - 1);

   ---------------------
   --  Standard Encrypt/Decrypt (separate buffers)
   ---------------------

   --  Encrypts plaintext, writes ciphertext + tag to output buffer
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
       Plaintext'Length <= Max_Buffer_Size
       and then Ciphertext'Length <= Max_Buffer_Size
       and then Ciphertext'Length >= Tag_Bytes
       and then Ciphertext'Length - Tag_Bytes >= Plaintext'Length;

   --  Decrypts ciphertext + tag, writes plaintext to output buffer
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
       Plaintext'Length <= Max_Buffer_Size
       and then Ciphertext'Length <= Max_Buffer_Size
       and then Ciphertext'Length >= Tag_Bytes
       and then Plaintext'Length >= Ciphertext'Length - Tag_Bytes;

   ---------------------
   --  In-Place Encrypt/Decrypt (for zero-copy TX/RX)
   ---------------------

   --  Encrypt plaintext in-place within a mutable buffer.
   --  The buffer must have the WireGuard transport packet layout:
   --    - Header at offset 0 (used as AAD, not modified)
   --    - Plaintext at offset Header_Bytes (encrypted in place)
   --    - Tag space reserved at end
   --
   --  Parameters:
   --    Buffer         : Mutable array covering entire packet region
   --    Plaintext_Len  : Length of plaintext (not including header or tag)
   --    Nonce          : 12-byte nonce (built from counter)
   --    Key            : 32-byte encryption key
   --    Result         : Success or error status
   --
   --  On success:
   --    - Bytes [Header_Bytes .. Header_Bytes+Plaintext_Len-1] contain ciphertext
   --    - Bytes [Header_Bytes+Plaintext_Len .. Header_Bytes+Plaintext_Len+15] contain the Poly1305 tag
   --    - Total packet length = Header_Bytes + Plaintext_Len + Tag_Bytes
   procedure Encrypt_In_Place
     (Buffer        : in out Byte_Array;
      Plaintext_Len : Natural;
      Nonce         : Nonce_Buffer;
      Key           : Key_Buffer;
      Result        : out Status)
   with
     Global => null,
     Pre    =>
       Buffer'Length <= Max_Buffer_Size
       and then Buffer'Length >= Header_Bytes + Tag_Bytes
       and then Plaintext_Len <= Buffer'Length - Header_Bytes - Tag_Bytes;

   --  Decrypt ciphertext in-place within a mutable buffer.
   --  The buffer must have the WireGuard transport packet layout:
   --    - Header at offset 0 (used as AAD verification)
   --    - Ciphertext + tag starting at offset Header_Bytes
   --
   --  Parameters:
   --    Buffer         : Mutable array covering entire packet
   --    Ciphertext_Len : Length of ciphertext INCLUDING the tag
   --    Nonce          : 12-byte nonce (built from counter in header)
   --    Key            : 32-byte decryption key
   --    Result         : Success if tag verified, Error_Failed otherwise
   --
   --  On success:
   --    - Bytes [Header_Bytes .. Header_Bytes+Ciphertext_Len-Tag_Bytes-1]
   --      contain the decrypted plaintext
   procedure Decrypt_In_Place
     (Buffer         : in out Byte_Array;
      Ciphertext_Len : Natural;
      Nonce          : Nonce_Buffer;
      Key            : Key_Buffer;
      Result         : out Status)
   with
     Global => null,
     Pre    =>
       Buffer'Length <= Max_Buffer_Size
       and then Ciphertext_Len <= Max_Buffer_Size
       and then Ciphertext_Len >= Tag_Bytes
       and then Buffer'Length >= Header_Bytes + Ciphertext_Len;

   ---------------------
   --  Utility Functions
   ---------------------

   --  Build a WireGuard nonce from counter: 0x00000000 || LE64(counter)
   procedure Build_Nonce (Counter : Unsigned_64; N : out Nonce_Buffer)
   with Post => (for all I in 0 .. 3 => N (I) = 0);

end Crypto.ChaCha20Poly1305;
