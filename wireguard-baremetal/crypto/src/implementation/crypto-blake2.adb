with Crypto.Blake2_Ref;
with Interfaces.C;

package body Crypto.Blake2
  with SPARK_Mode => Off
is
   procedure Blake2s
     (Buffer_Out : out Byte_Array;
      Buffer_In  : Byte_Array;
      Key_Buffer : Byte_Array;
      Result     : out Crypto.Status)
   is
      use Interfaces.C;
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
end Crypto.Blake2;
