with Crypto.Blake2_Ref;
with System;

package body Crypto.Blake2
  with SPARK_Mode => Off
is
   --  Unkeyed hash
   procedure Blake2s
     (Data   : Byte_Array;
      Digest : out Digest_Buffer;
      Result : out Crypto.Status)
   is
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Blake2_Ref.Blake2s
          (Buffer_Out      => Digest'Address,
           Buffer_Out_Size => size_t (Digest'Length),
           Buffer_In       => Data'Address,
           Buffer_In_Size  => size_t (Data'Length),
           Key_In          => System.Null_Address,
           Key_In_Size     => 0);

      if Ret_Val = 0 then
         Result := Crypto.Success;
      else
         Result := Crypto.Error_Failed;
      end if;
   end Blake2s;

   --  Keyed hash
   procedure Blake2s
     (Data   : Byte_Array;
      Key    : Key_Buffer;
      Digest : out Digest_Buffer;
      Result : out Crypto.Status)
   is
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Blake2_Ref.Blake2s
          (Buffer_Out      => Digest'Address,
           Buffer_Out_Size => size_t (Digest'Length),
           Buffer_In       => Data'Address,
           Buffer_In_Size  => size_t (Data'Length),
           Key_In          => Key'Address,
           Key_In_Size     => size_t (Key'Length));

      if Ret_Val = 0 then
         Result := Crypto.Success;
      else
         Result := Crypto.Error_Failed;
      end if;
   end Blake2s;

   procedure Blake2s_Init
     (Outlen : Digest_Length;
      State  : aliased out Blake2s_State;
      Result : out Crypto.Status)
   is
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Blake2_Ref.Blake2s_Init
          (State => State'Unchecked_Access, Outlen => size_t (Outlen));

      if Ret_Val = 0 then
         Result := Crypto.Success;
      else
         Result := Crypto.Error_Failed;
      end if;
   end Blake2s_Init;

   procedure Blake2s_Init_Key
     (Key    : Key_Buffer;
      Outlen : Digest_Length;
      State  : aliased out Blake2s_State;
      Result : out Crypto.Status)
   is
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Blake2_Ref.Blake2s_Init_Key
          (State  => State'Unchecked_Access,
           Outlen => size_t (Outlen),
           Key_In => Key'Address,
           Keylen => size_t (Key'Length));

      if Ret_Val = 0 then
         Result := Crypto.Success;
      else
         Result := Crypto.Error_Failed;
      end if;
   end Blake2s_Init_Key;

   procedure Blake2s_Update
     (Data   : Byte_Array;
      State  : aliased in out Blake2s_State;
      Result : out Crypto.Status)
   is
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Blake2_Ref.Blake2s_Update
          (State => State'Unchecked_Access,
           Data  => Data'Address,
           Len   => size_t (Data'Length));

      if Ret_Val = 0 then
         Result := Crypto.Success;
      else
         Result := Crypto.Error_Failed;
      end if;
   end Blake2s_Update;

   procedure Blake2s_Final
     (State  : aliased in out Blake2s_State;
      Digest : out Byte_Array;
      Result : out Crypto.Status)
   is
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Blake2_Ref.Blake2s_Final
          (State  => State'Unchecked_Access,
           Output => Digest'Address,
           Outlen => size_t (Digest'Length));

      if Ret_Val = 0 then
         Result := Crypto.Success;
      else
         Result := Crypto.Error_Failed;
      end if;
   end Blake2s_Final;

end Crypto.Blake2;
