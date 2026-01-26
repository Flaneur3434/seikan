--  X25519 Elliptic Curve Diffie-Hellman
--
--  Provides key generation and key exchange using Curve25519.
--  This is the public interface; implementations are platform-specific.

with Interfaces;
with Utils; use Utils;

package Crypto.X25519
  with SPARK_Mode => On
is
   use Interfaces;

   --  X25519 Constants
   Scalarmult_Bytes        : constant Positive := 32;  --  Public key size
   Scalarmult_Scalar_Bytes : constant Positive := 32;  --  Secret key size

   --  X25519 Types
   type Public_Key is array (0 .. Scalarmult_Bytes - 1) of Unsigned_8;
   type Secret_Key is array (0 .. Scalarmult_Scalar_Bytes - 1) of Unsigned_8;
   type Shared_Secret is array (0 .. Scalarmult_Bytes - 1) of Unsigned_8;

   type Key_Pair is record
      Pub : Public_Key;
      Sec : Secret_Key;
   end record;

   --  Generate a new random keypair
   procedure Generate_Key_Pair (Key : out Key_Pair; Result : out Status)
   with Global => null;

   --  Compute public key from existing secret key
   --  Pub = Sec × BasePoint
   procedure Scalar_Mult_Base
     (Pub : out Public_Key; Sec : Secret_Key; Result : out Status)
   with Global => null;

   --  Compute shared secret via Diffie-Hellman
   --  Shared = My_Secret × Their_Public
   procedure Scalar_Mult
     (Shared       : out Shared_Secret;
      My_Secret    : Secret_Key;
      Their_Public : Public_Key;
      Result       : out Status)
   with Global => null;

end Crypto.X25519;
