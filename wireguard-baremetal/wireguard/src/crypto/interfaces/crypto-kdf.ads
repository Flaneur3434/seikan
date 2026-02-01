--  WireGuard Key Derivation Functions
--
--  Implements HKDF using HMAC-BLAKE2s as specified in the WireGuard protocol.
--
--  From the whitepaper:
--    Hmac(key, input) = Hmac-Blake2s(key, input, 32)
--    Kdf_n(key, input) = τ0 := Hmac(key, input),
--                        τ1 := Hmac(τ0, 0x1),
--                        τi := Hmac(τ0, τi-1 ‖ i)
--                        returns (τ1, ..., τn)
--
--  This is the HKDF construction from RFC 5869.

with Utils; use Utils;

package Crypto.KDF
  with SPARK_Mode => On
is

   --  Output size constants
   Hash_Len : constant := 32;  --  BLAKE2s-256 output

   --  Key/output types
   subtype KDF_Key is Byte_Array (0 .. Hash_Len - 1);

   ---------------------
   --  HMAC-BLAKE2s
   ---------------------

   --  HMAC using BLAKE2s as the underlying hash function.
   --  Output is always 32 bytes (BLAKE2s-256).
   procedure HMAC_Blake2s
     (Key    : Byte_Array;
      Data   : Byte_Array;
      Output : out KDF_Key;
      Result : out Status)
   with
     Global => null,
     Pre    => Key'Length <= 64;  --  BLAKE2s block size

   ---------------------
   --  HKDF Functions (WireGuard style)
   ---------------------

   --  KDF1: Derives one 32-byte key
   --  τ0 := HMAC(key, input)
   --  τ1 := HMAC(τ0, 0x01)
   --  Returns τ1
   procedure KDF1
     (Key    : KDF_Key;
      Input  : Byte_Array;
      Output : out KDF_Key;
      Result : out Status)
   with Global => null;

   --  KDF2: Derives two 32-byte keys
   --  τ0 := HMAC(key, input)
   --  τ1 := HMAC(τ0, 0x01)
   --  τ2 := HMAC(τ0, τ1 ‖ 0x02)
   --  Returns (τ1, τ2)
   procedure KDF2
     (Key     : KDF_Key;
      Input   : Byte_Array;
      Output1 : out KDF_Key;
      Output2 : out KDF_Key;
      Result  : out Status)
   with Global => null;

   --  KDF3: Derives three 32-byte keys
   --  τ0 := HMAC(key, input)
   --  τ1 := HMAC(τ0, 0x01)
   --  τ2 := HMAC(τ0, τ1 ‖ 0x02)
   --  τ3 := HMAC(τ0, τ2 ‖ 0x03)
   --  Returns (τ1, τ2, τ3)
   procedure KDF3
     (Key     : KDF_Key;
      Input   : Byte_Array;
      Output1 : out KDF_Key;
      Output2 : out KDF_Key;
      Output3 : out KDF_Key;
      Result  : out Status)
   with Global => null;

end Crypto.KDF;
