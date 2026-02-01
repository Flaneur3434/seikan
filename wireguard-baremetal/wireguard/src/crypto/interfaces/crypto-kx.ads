--  Key Exchange Interface
--
--  Generic key exchange interface that works with any crypto backend.
--  Provides key generation and Diffie-Hellman key agreement.
--
--  This is the public interface; implementations delegate to Crypto.Platform.
--  Field sizes are defined by the platform layer, allowing different backends
--  (libsodium, libhydrogen, etc.) with potentially different sizes.

with Interfaces;
with Utils; use Utils;
with Crypto.Config;

package Crypto.KX
  with SPARK_Mode => On
is
   use Interfaces;

   --  Key Exchange Constants (from platform config)
   Public_Key_Bytes  : constant Positive := Crypto.Config.KX_Public_Key_Bytes;
   Secret_Key_Bytes  : constant Positive := Crypto.Config.KX_Secret_Key_Bytes;
   Shared_Key_Bytes  : constant Positive := Crypto.Config.KX_Shared_Key_Bytes;

   --  Key Exchange Types
   type Public_Key is array (0 .. Public_Key_Bytes - 1) of Unsigned_8;
   type Secret_Key is array (0 .. Secret_Key_Bytes - 1) of Unsigned_8;
   type Shared_Secret is array (0 .. Shared_Key_Bytes - 1) of Unsigned_8;

   type Key_Pair is record
      Pub : Public_Key;
      Sec : Secret_Key;
   end record;

   --  Generate a new random keypair
   procedure Generate_Key_Pair (Key : out Key_Pair; Result : out Status)
   with Global => null;

   --  Compute public key from existing secret key
   --  Pub = DerivePublic(Sec)
   procedure Derive_Public_Key
     (Pub : out Public_Key; Sec : Secret_Key; Result : out Status)
   with Global => null;

   --  Compute shared secret via Diffie-Hellman
   --  Shared = DH(My_Secret, Their_Public)
   procedure DH
     (Shared       : out Shared_Secret;
      My_Secret    : Secret_Key;
      Their_Public : Public_Key;
      Result       : out Status)
   with Global => null;

end Crypto.KX;
