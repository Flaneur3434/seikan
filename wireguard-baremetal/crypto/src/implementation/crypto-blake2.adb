with Crypto.Blake2_Ref;

package body Crypto.Blake2
  with SPARK_Mode => Off
is
   procedure Blake2s
     (Buffer_Out : out Byte_Array;
      Buffer_In  : Byte_Array;
      Key_Buffer : Byte_Array;
      Result     : out Crypto.Status)
   is
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Blake2_Ref.Blake2s
          (Buffer_Out      => Buffer_Out'Address,
           Buffer_Out_Size => size_t (Buffer_Out'Length),
           Buffer_In       => Buffer_In'Address,
           Buffer_In_Size  => size_t (Buffer_In'Length),
           Key_In          => Key_Buffer'Address,
           Key_In_Size     => size_t (Key_Buffer'Length));

      if Ret_Val = 0 then
         Result := Crypto.Success;
      else
         Result := Crypto.Error_Failed;
      end if;
   end Blake2s;

   procedure Blake2s_Init
     (State  : aliased out Blake2s_State;
      Outlen : Positive;
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
     (State  : aliased out Blake2s_State;
      Outlen : Positive;
      Key    : Byte_Array;
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
     (State  : aliased in out Blake2s_State;
      Data   : Byte_Array;
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
