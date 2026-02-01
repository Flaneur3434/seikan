--  Crypto library bindings: libsodium
--
--  This is a PRIVATE package - only visible within Crypto hierarchy.
--  Provides bindings to libsodium for key exchange and AEAD operations.
--
--  Backend: libsodium (X25519, ChaCha20-Poly1305 IETF)
--
--  NOTE: sodium_init() is called automatically during package elaboration.

with System;
with Interfaces.C;

private package Crypto.Crypto_Lib
  with
    SPARK_Mode => Off,
    Elaborate_Body
is
   use Interfaces.C;

   ---------------------
   --  Initialization
   ---------------------

   --  Initialize the crypto library. Must be called before any other function.
   --  Returns 0 on success, 1 if already initialized, -1 on failure.
   function Init return int
   with Import, Convention => C, External_Name => "sodium_init";

   ---------------------
   --  Key Generation & Exchange
   ---------------------

   --  Generates a random keypair for key exchange.
   --  Public_Key_Out: 32 bytes, Secret_Key_Out: 32 bytes
   function Generate_Keypair
     (Public_Key_Out : System.Address; Secret_Key_Out : System.Address)
      return int
   with Import, Convention => C, External_Name => "crypto_box_keypair";

   --  Derives public key from secret key.
   --  Public_Key_Out: 32 bytes, Secret_Key_In: 32 bytes
   function Derive_Public_Key
     (Public_Key_Out : System.Address; Secret_Key_In : System.Address)
      return int
   with Import, Convention => C, External_Name => "crypto_scalarmult_base";

   --  Computes shared secret from my secret key and their public key.
   --  Shared_Secret_Out: 32 bytes
   --  This is the Diffie-Hellman key agreement operation.
   function DH_Key_Exchange
     (Shared_Secret_Out   : System.Address;
      My_Secret_Key_In    : System.Address;
      Their_Public_Key_In : System.Address) return int
   with Import, Convention => C, External_Name => "crypto_scalarmult";

   ---------------------
   --  Authenticated Encryption (AEAD)
   ---------------------

   --  Encrypts and authenticates a message.
   --  Ciphertext_Out: Message_Len + 16 bytes (tag)
   --  Nonce_In: 12 bytes, Key_In: 32 bytes
   --  Returns 0 on success.
   function AEAD_Encrypt
     (Ciphertext_Out     : System.Address;
      Ciphertext_Len_Out : System.Address;
      Message_In         : System.Address;
      Message_Len        : unsigned_long_long;
      Ad_In              : System.Address;
      Ad_Len             : unsigned_long_long;
      Nsec               : System.Address;
      Nonce_In           : System.Address;
      Key_In             : System.Address) return int
   with
     Import,
     Convention    => C,
     External_Name => "crypto_aead_chacha20poly1305_ietf_encrypt";

   --  Decrypts and verifies ciphertext.
   --  Returns 0 on success, -1 if authentication fails.
   --  On failure, plaintext buffer is zeroed.
   function AEAD_Decrypt
     (Message_Out     : System.Address;
      Message_Len_Out : System.Address;
      Nsec            : System.Address;
      Ciphertext_In   : System.Address;
      Ciphertext_Len  : unsigned_long_long;
      Ad_In           : System.Address;
      Ad_Len          : unsigned_long_long;
      Nonce_In        : System.Address;
      Key_In          : System.Address) return int
   with
     Import,
     Convention    => C,
     External_Name => "crypto_aead_chacha20poly1305_ietf_decrypt";

   ---------------------
   --  Utility Functions
   ---------------------

   --  Securely zeros memory (not optimized away by compiler).
   procedure Secure_Wipe (Buffer : System.Address; Size : size_t)
   with Import, Convention => C, External_Name => "sodium_memzero";

   --  Constant-time memory comparison.
   --  Returns 0 if equal, -1 if different.
   function Constant_Time_Compare
     (A : System.Address; B : System.Address; Length : size_t) return int
   with Import, Convention => C, External_Name => "sodium_memcmp";

end Crypto.Crypto_Lib;
