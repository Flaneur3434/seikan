--  Platform-specific crypto bindings: libsodium
--
--  This is a PRIVATE package - only visible within Crypto hierarchy.
--  Libsodium works on both ESP32 (via ESP-IDF component) and host.
--
--  NOTE: sodium_init() is called automatically during package elaboration.

with System;
with Interfaces.C;

private package Crypto.Platform
  with SPARK_Mode => Off,
       Elaborate_Body  --  Ensures body runs to call sodium_init
is
   use Interfaces.C;

   ---------------------
   --  Initialization
   ---------------------

   --  int sodium_init(void);
   --  Returns 0 on success, 1 if already initialized, -1 on failure
   function Sodium_Init return int
   with Import, Convention => C, External_Name => "sodium_init";

   ---------------------
   --  Random Number Generation
   ---------------------

   --  void randombytes_buf(void * const buf, const size_t size);
   --  Fills buffer with cryptographically secure random bytes
   procedure Randombytes_Buf
     (Buffer : System.Address;
      Size   : size_t)
   with Import, Convention => C, External_Name => "randombytes_buf";

   ---------------------
   --  X25519 Key Exchange
   ---------------------

   --  int crypto_box_keypair(unsigned char *pk, unsigned char *sk);
   --  Generates a random X25519 keypair
   function Crypto_Box_Keypair
     (Public_Key_Out : System.Address;
      Secret_Key_Out : System.Address)
      return int
   with Import, Convention => C, External_Name => "crypto_box_keypair";

   --  int crypto_scalarmult_base(unsigned char *q, const unsigned char *n);
   --  Computes public key from secret key: q = n × BasePoint
   function Crypto_Scalarmult_Base
     (Public_Key_Out : System.Address;
      Secret_Key_In  : System.Address)
      return int
   with Import, Convention => C, External_Name => "crypto_scalarmult_base";

   --  int crypto_scalarmult(unsigned char *q, const unsigned char *n,
   --                        const unsigned char *p);
   --  Computes shared secret: q = n × p (Diffie-Hellman)
   function Crypto_Scalarmult
     (Shared_Secret_Out   : System.Address;
      My_Secret_Key_In    : System.Address;
      Their_Public_Key_In : System.Address)
      return int
   with Import, Convention => C, External_Name => "crypto_scalarmult";

   -- int crypto_aead_chacha20poly1305_ietf_encrypt(unsigned char *c,
   --                                               unsigned long long *clen_p,
   --                                               const unsigned char *m,
   --                                               unsigned long long mlen,
   --                                               const unsigned char *ad,
   --                                               unsigned long long adlen,
   --                                               const unsigned char *nsec,
   --                                               const unsigned char *npub,
   --                                               const unsigned char *k)
   -- Encrypts a message using a secret key and public nonce. The out buffer 
   -- contains a combination of the encrypted message and authentication tag.
   function Crypto_AEAD_ChaCha20Poly1305_IETF_Encrypt
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

   --  int crypto_aead_chacha20poly1305_ietf_decrypt(unsigned char *m,
   --                                                unsigned long long *mlen_p,
   --                                                unsigned char *nsec,
   --                                                const unsigned char *c,
   --                                                unsigned long long clen,
   --                                                const unsigned char *ad,
   --                                                unsigned long long adlen,
   --                                                const unsigned char *npub,
   --                                                const unsigned char *k)
   --  Decrypts ciphertext and verifies authentication tag.
   --  Returns 0 on success, -1 if verification fails (invalid tag).
   --  On failure, plaintext buffer is zeroed.
   function Crypto_AEAD_ChaCha20Poly1305_IETF_Decrypt
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
   --  Future: Add more bindings here
   --  - BLAKE2b
   --  - etc.
   ---------------------

end Crypto.Platform;
