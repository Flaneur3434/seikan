package body Utils.Memory_Pool
   with SPARK_Mode    => On,
        Refined_State => (Pool_State => (Memory,
                                         Free_Stack,
                                         Free_Top))
is
   type Pool_Array is array (Pool_Index) of Packet_Buffer;
   type Index_Stack is array (Pool_Index) of Pool_Index;

   Memory     : Pool_Array;
   Free_Stack : Index_Stack;
   Free_Top   : Integer := -1;  --  -1 means empty

   procedure Initialize is
   begin
      --  Push all indices onto free stack
      for I in Pool_Index loop
         Free_Stack (I) := I;
      end loop;
      Free_Top := Pool_Size - 1;

      --  Clear memory
      Memory := (others => (others => 0));
   end Initialize;

   procedure Allocate (Desc : out Buffer_Descriptor) is
      Idx : Pool_Index;
   begin
      if Free_Top < 0 then
         Desc := Null_Descriptor;
         return;
      end if;

      Idx := Free_Stack (Free_Top);
      Free_Top := Free_Top - 1;

      Desc := (Idx     => Idx,
               Address => Memory (Idx)'Address,
               In_Use  => True);
   end Allocate;

   procedure Free (Desc : in out Buffer_Descriptor) is
   begin
      Free_Top := Free_Top + 1;
      Free_Stack (Free_Top) := Desc.Idx;

      --  Clear buffer memory
      Memory (Desc.Idx) := (others => 0);
      Desc := Null_Descriptor;
   end Free;

   function Get_Buffer (Desc : Buffer_Descriptor) return Packet_Buffer is
   begin
      return Memory (Desc.Idx);
   end Get_Buffer;

   procedure Set_Buffer (Desc : Buffer_Descriptor; Data : Packet_Buffer) is
   begin
      Memory (Desc.Idx) := Data;
   end Set_Buffer;

   function Get_Address (Desc : Buffer_Descriptor) return System.Address is
   begin
      return Memory (Desc.Idx)'Address;
   end Get_Address;

end Utils.Memory_Pool;
