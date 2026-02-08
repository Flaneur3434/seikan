--  WireGuard KDF implementation using BLAKE2s streaming API

with Crypto.Blake2_Ref;
with Crypto.Helper;
with System;
with Interfaces; use Interfaces;
with Interfaces.C; use Interfaces.C;

package body Crypto.KDF
  with SPARK_Mode => Off
is
   --  Local secure-wipe for Byte_Array (generic instance)
   procedure Memzero is new Crypto.Helper.Generic_Memzero (Byte_Array);

   --  BLAKE2s block size for HMAC
   Block_Size : constant := 64;

   --  HMAC ipad/opad constants
   IPAD : constant Unsigned_8 := 16#36#;
   OPAD : constant Unsigned_8 := 16#5C#;

   ---------------------
   --  HMAC-BLAKE2s Implementation
   ---------------------

   procedure HMAC_Blake2s
     (Key    : Byte_Array;
      Data   : Byte_Array;
      Output : out KDF_Key;
      Result : out Status)
   is
      --  Padded key (block size)
      K_Pad : aliased Byte_Array (0 .. Block_Size - 1) := (others => 0);

      --  Inner and outer padded keys
      K_Ipad : aliased Byte_Array (0 .. Block_Size - 1);
      K_Opad : aliased Byte_Array (0 .. Block_Size - 1);

      --  Inner hash result
      Inner_Hash : aliased KDF_Key;

      --  BLAKE2s state
      State : aliased Crypto.Blake2_Ref.Blake2s_State;
      Ret   : int;
   begin
      --  Step 1: Prepare key (pad or hash if needed)
      if Key'Length <= Block_Size then
         --  Pad key with zeros
         K_Pad (0 .. Key'Length - 1) := Key;
      else
         --  Key too long - hash it first (rare case)
         Ret := Crypto.Blake2_Ref.Blake2s
           (Buffer_Out      => K_Pad'Address,
            Buffer_Out_Size => Hash_Len,
            Buffer_In       => Key'Address,
            Buffer_In_Size  => Key'Length,
            Key_In          => System.Null_Address,
            Key_In_Size     => 0);
         if Ret /= 0 then
            Output := (others => 0);
            Result := Error_Failed;
            return;
         end if;
      end if;

      --  Step 2: Create ipad and opad keys
      for I in K_Pad'Range loop
         K_Ipad (I) := K_Pad (I) xor IPAD;
         K_Opad (I) := K_Pad (I) xor OPAD;
      end loop;

      --  Step 3: Inner hash = BLAKE2s(K_ipad || data)
      Ret := Crypto.Blake2_Ref.Blake2s_Init
        (State'Unchecked_Access, Hash_Len);
      if Ret /= 0 then
         Output := (others => 0);
         Result := Error_Failed;
         return;
      end if;

      Ret := Crypto.Blake2_Ref.Blake2s_Update
        (State'Unchecked_Access, K_Ipad'Address, K_Ipad'Length);
      if Ret /= 0 then
         Output := (others => 0);
         Result := Error_Failed;
         return;
      end if;

      if Data'Length > 0 then
         Ret := Crypto.Blake2_Ref.Blake2s_Update
           (State'Unchecked_Access, Data'Address, Data'Length);
         if Ret /= 0 then
            Output := (others => 0);
            Result := Error_Failed;
            return;
         end if;
      end if;

      Ret := Crypto.Blake2_Ref.Blake2s_Final
        (State'Unchecked_Access, Inner_Hash'Address, Hash_Len);
      if Ret /= 0 then
         Output := (others => 0);
         Result := Error_Failed;
         return;
      end if;

      --  Step 4: Outer hash = BLAKE2s(K_opad || inner_hash)
      Ret := Crypto.Blake2_Ref.Blake2s_Init
        (State'Unchecked_Access, Hash_Len);
      if Ret /= 0 then
         Output := (others => 0);
         Result := Error_Failed;
         return;
      end if;

      Ret := Crypto.Blake2_Ref.Blake2s_Update
        (State'Unchecked_Access, K_Opad'Address, K_Opad'Length);
      if Ret /= 0 then
         Output := (others => 0);
         Result := Error_Failed;
         return;
      end if;

      Ret := Crypto.Blake2_Ref.Blake2s_Update
        (State'Unchecked_Access, Inner_Hash'Address, Hash_Len);
      if Ret /= 0 then
         Output := (others => 0);
         Result := Error_Failed;
         return;
      end if;

      Ret := Crypto.Blake2_Ref.Blake2s_Final
        (State'Unchecked_Access, Output'Address, Hash_Len);
      if Ret /= 0 then
         Output := (others => 0);
         Result := Error_Failed;
         return;
      end if;

      Result := Success;
   end HMAC_Blake2s;

   ---------------------
   --  KDF1
   ---------------------

   procedure KDF1
     (Key    : KDF_Key;
      Input  : Byte_Array;
      Output : out KDF_Key;
      Result : out Status)
   is
      Tau0   : KDF_Key;
      Label  : constant Byte_Array (0 .. 0) := (0 => 16#01#);
   begin
      --  τ0 := HMAC(key, input)
      HMAC_Blake2s (Key, Input, Tau0, Result);
      if Result /= Success then
         Output := (others => 0);
         return;
      end if;

      --  τ1 := HMAC(τ0, 0x01)
      HMAC_Blake2s (Tau0, Label, Output, Result);
      if Result /= Success then
         Output := (others => 0);
      end if;

      --  Clear intermediate value
      Memzero (Tau0);
   end KDF1;

   ---------------------
   --  KDF2
   ---------------------

   procedure KDF2
     (Key     : KDF_Key;
      Input   : Byte_Array;
      Output1 : out KDF_Key;
      Output2 : out KDF_Key;
      Result  : out Status)
   is
      Tau0      : KDF_Key;
      Label1    : constant Byte_Array (0 .. 0) := (0 => 16#01#);
      Tau1_Cat  : Byte_Array (0 .. Hash_Len);  --  τ1 || 0x02
   begin
      --  τ0 := HMAC(key, input)
      HMAC_Blake2s (Key, Input, Tau0, Result);
      if Result /= Success then
         Output1 := (others => 0);
         Output2 := (others => 0);
         return;
      end if;

      --  τ1 := HMAC(τ0, 0x01)
      HMAC_Blake2s (Tau0, Label1, Output1, Result);
      if Result /= Success then
         Output1 := (others => 0);
         Output2 := (others => 0);
         Tau0 := (others => 0);
         return;
      end if;

      --  τ2 := HMAC(τ0, τ1 || 0x02)
      Tau1_Cat (0 .. Hash_Len - 1) := Output1;
      Tau1_Cat (Hash_Len) := 16#02#;
      HMAC_Blake2s (Tau0, Tau1_Cat, Output2, Result);
      if Result /= Success then
         Output1 := (others => 0);
         Output2 := (others => 0);
      end if;

      --  Clear intermediate values
      Memzero (Tau0);
      Memzero (Tau1_Cat);
   end KDF2;

   ---------------------
   --  KDF3
   ---------------------

   procedure KDF3
     (Key     : KDF_Key;
      Input   : Byte_Array;
      Output1 : out KDF_Key;
      Output2 : out KDF_Key;
      Output3 : out KDF_Key;
      Result  : out Status)
   is
      Tau0      : KDF_Key;
      Label1    : constant Byte_Array (0 .. 0) := (0 => 16#01#);
      Prev_Cat  : Byte_Array (0 .. Hash_Len);  --  τ_prev || label
   begin
      --  τ0 := HMAC(key, input)
      HMAC_Blake2s (Key, Input, Tau0, Result);
      if Result /= Success then
         Output1 := (others => 0);
         Output2 := (others => 0);
         Output3 := (others => 0);
         return;
      end if;

      --  τ1 := HMAC(τ0, 0x01)
      HMAC_Blake2s (Tau0, Label1, Output1, Result);
      if Result /= Success then
         Output1 := (others => 0);
         Output2 := (others => 0);
         Output3 := (others => 0);
         Tau0 := (others => 0);
         return;
      end if;

      --  τ2 := HMAC(τ0, τ1 || 0x02)
      Prev_Cat (0 .. Hash_Len - 1) := Output1;
      Prev_Cat (Hash_Len) := 16#02#;
      HMAC_Blake2s (Tau0, Prev_Cat, Output2, Result);
      if Result /= Success then
         Output1 := (others => 0);
         Output2 := (others => 0);
         Output3 := (others => 0);
         Tau0 := (others => 0);
         Prev_Cat := (others => 0);
         return;
      end if;

      --  τ3 := HMAC(τ0, τ2 || 0x03)
      Prev_Cat (0 .. Hash_Len - 1) := Output2;
      Prev_Cat (Hash_Len) := 16#03#;
      HMAC_Blake2s (Tau0, Prev_Cat, Output3, Result);
      if Result /= Success then
         Output1 := (others => 0);
         Output2 := (others => 0);
         Output3 := (others => 0);
      end if;

      --  Clear intermediate values
      Memzero (Tau0);
      Memzero (Prev_Cat);
   end KDF3;

end Crypto.KDF;
