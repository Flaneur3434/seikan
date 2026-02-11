--  Authenticated Encryption with Associated Data (AEAD) Interface
--
--  Generic AEAD interface that works with any crypto backend.
--  Encrypts and provides integrity for messages.
--
--  This is the public interface; implementations delegate to Crypto.Platform.
--  Field sizes are defined by the platform layer, allowing different backends
--  (libsodium with ChaCha20-Poly1305, libhydrogen with Gimli secretbox, etc.)
--
--  ZERO-COPY DESIGN
--    - Uses native Ada arrays (passed by reference automatically)
--    - In-place encryption overwrites plaintext with ciphertext
--
--  IN-PLACE ENCRYPTION (for TX path)
--    Buffer layout before encryption:
--      [0..Header_Bytes-1]           = Transport header (AAD)
--      [Header_Bytes..Header+PT-1]   = Plaintext payload
--      [Header+PT..Header+PT+Tag-1]  = Reserved for auth tag
--
--    After encryption:
--      [0..Header_Bytes-1]           = Transport header (unchanged)
--      [Header_Bytes..Header+PT-1]   = Ciphertext (overwrites plaintext)
--      [Header+PT..Header+PT+Tag-1]  = Authentication tag

with Interfaces;
with Utils; use Utils;
with Crypto.Config;

package Crypto.AEAD
  with SPARK_Mode => On
is
   use Interfaces;

   --  AEAD Constants (from platform config)
   Key_Bytes   : constant Positive := Crypto.Config.AEAD_Key_Bytes;
   Nonce_Bytes : constant Natural  := Crypto.Config.AEAD_Nonce_Bytes;
   Tag_Bytes   : constant Positive := Crypto.Config.AEAD_Tag_Bytes;

   --  Transport Header size (protocol-defined, not backend-specific)
   Header_Bytes : constant Positive := 16;

   --  Maximum buffer size for precondition proofs
   Max_Buffer_Size : constant := Utils.Max_Packet_Size;

   --  AEAD Types
   subtype Key_Buffer is Byte_Array (0 .. Key_Bytes - 1);

   --  Nonce buffer - may be empty for backends that handle nonces internally
   --  Note: When Nonce_Bytes = 0, this creates an empty range array
   subtype Nonce_Buffer is Byte_Array (0 .. Natural'Max (Nonce_Bytes, 1) - 1);

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

   --  Build a nonce from counter: backend-specific format
   --  For libsodium (12-byte): 0x00000000 || LE64(counter)
   --  For libhydrogen (0-byte): no-op, counter managed internally
   procedure Build_Nonce (Counter : Unsigned_64; N : out Nonce_Buffer);

end Crypto.AEAD;
