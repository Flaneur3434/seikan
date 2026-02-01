--  Crypto library bindings: libhydrogen
--
--  This is a PRIVATE package - only visible within Crypto hierarchy.
--  Provides bindings to libhydrogen for key exchange and AEAD operations.
--
--  Backend: libhydrogen (Gimli-based primitives)
--
--  NOTE: hydro_init() is called automatically during package elaboration.

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
   --  Returns 0 on success, -1 on failure.
   function Init return int
   with Import, Convention => C, External_Name => "hydro_init";

   ---------------------
   --  Key Generation & Exchange
   ---------------------

   --  Generates a random keypair for key exchange.
   --  Public_Key_Out: 32 bytes, Secret_Key_Out: 32 bytes
   --  Wrapper around hydro_kx_keygen
   function Generate_Keypair
     (Public_Key_Out : System.Address; Secret_Key_Out : System.Address)
      return int;

   --  Derives public key from secret key.
   --  Public_Key_Out: 32 bytes, Secret_Key_In: 32 bytes
   --  Wrapper using hydro_kx_keygen_deterministic
   function Derive_Public_Key
     (Public_Key_Out : System.Address; Secret_Key_In : System.Address)
      return int;

   --  Computes shared secret from my secret key and their public key.
   --  Shared_Secret_Out: 32 bytes
   --  NOTE: libhydrogen doesn't expose raw DH, uses hash-based derivation.
   function DH_Key_Exchange
     (Shared_Secret_Out   : System.Address;
      My_Secret_Key_In    : System.Address;
      Their_Public_Key_In : System.Address) return int;

   ---------------------
   --  Authenticated Encryption (AEAD)
   ---------------------

   --  Encrypts and authenticates a message.
   --  Ciphertext_Out: Message_Len + 36 bytes (header)
   --  Nonce_In: 12 bytes (first 8 used as msg_id), Key_In: 32 bytes
   --  Returns 0 on success.
   --  NOTE: libhydrogen doesn't support additional data (AD is ignored).
   function AEAD_Encrypt
     (Ciphertext_Out     : System.Address;
      Ciphertext_Len_Out : System.Address;
      Message_In         : System.Address;
      Message_Len        : unsigned_long_long;
      Ad_In              : System.Address;
      Ad_Len             : unsigned_long_long;
      Nsec               : System.Address;
      Nonce_In           : System.Address;
      Key_In             : System.Address) return int;

   --  Decrypts and verifies ciphertext.
   --  Returns 0 on success, -1 if authentication fails.
   function AEAD_Decrypt
     (Message_Out     : System.Address;
      Message_Len_Out : System.Address;
      Nsec            : System.Address;
      Ciphertext_In   : System.Address;
      Ciphertext_Len  : unsigned_long_long;
      Ad_In           : System.Address;
      Ad_Len          : unsigned_long_long;
      Nonce_In        : System.Address;
      Key_In          : System.Address) return int;

   ---------------------
   --  Utility Functions
   ---------------------

   --  Securely zeros memory (not optimized away by compiler).
   procedure Secure_Wipe (Buffer : System.Address; Size : size_t)
   with Import, Convention => C, External_Name => "hydro_memzero";

   --  Constant-time memory comparison.
   --  Returns 0 if equal, -1 if different.
   --  Wrapper around hydro_equal (which returns bool).
   function Constant_Time_Compare
     (A : System.Address; B : System.Address; Length : size_t) return int;

end Crypto.Crypto_Lib;
