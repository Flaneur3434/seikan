--  X25519 Elliptic Curve Diffie-Hellman
--
--  Provides key generation and key exchange using Curve25519.
--  This is the public interface; implementations are platform-specific.

package Crypto.X25519
  with SPARK_Mode => On
is
   --  Generate a new random keypair
   procedure Generate_Key_Pair
     (Key    : out Key_Pair;
      Result : out Crypto.Status)
   with Global => null;

   --  Compute public key from existing secret key
   --  Public_Key = Secret_Key × BasePoint
   procedure Scalar_Mult_Base
     (Public_Key : out X25519_Public_Key;
      Secret_Key : X25519_Secret_Key;
      Result     : out Crypto.Status)
   with Global => null;

   --  Compute shared secret via Diffie-Hellman
   --  Shared_Secret = My_Secret × Their_Public
   procedure Scalar_Mult
     (Shared_Secret : out X25519_Shared_Secret;
      My_Secret     : X25519_Secret_Key;
      Their_Public  : X25519_Public_Key;
      Result        : out Crypto.Status)
   with Global => null;

end Crypto.X25519;
