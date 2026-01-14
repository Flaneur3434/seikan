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

   ---------------------
   --  Future: Add more bindings here
   --  - ChaCha20-Poly1305
   --  - BLAKE2b
   --  - etc.
   ---------------------

end Crypto.Platform;
