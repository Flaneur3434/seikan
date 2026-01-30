--  Packet_Pool - C FFI Implementation

package body Packet_Pool
   with SPARK_Mode => Off
is
   --  Internal storage for tracking descriptors by handle
   type Descriptor_Array is array (Pool.Pool_Index) of Buffer_Descriptor;

   Descriptors : Descriptor_Array := (others => Null_Descriptor);

   ---------------------------------------------------------------------------
   --  C FFI Implementations
   ---------------------------------------------------------------------------

   procedure C_Pool_Init is
   begin
      Initialize;
      Descriptors := (others => Null_Descriptor);
   end C_Pool_Init;

   function C_Pool_Allocate return C_Buffer_Handle is
      Desc : Buffer_Descriptor;
   begin
      Allocate (Desc);

      if not Desc.In_Use then
         return Invalid_Handle;
      end if;

      --  Store descriptor and return handle (index)
      Descriptors (Desc.Idx) := Desc;
      return C_Buffer_Handle (Desc.Idx);
   end C_Pool_Allocate;

   procedure C_Pool_Free (Handle : C_Buffer_Handle) is
   begin
      if Handle < 0 or else Handle >= C_Buffer_Handle (Pool_Size) then
         return;
      end if;

      declare
         Idx  : constant Pool.Pool_Index := Pool.Pool_Index (Handle);
         Desc : Buffer_Descriptor := Descriptors (Idx);
      begin
         if not Desc.In_Use then
            return;
         end if;

         Free (Desc);
         Descriptors (Idx) := Desc;  --  Now Null_Descriptor
      end;
   end C_Pool_Free;

   function C_Pool_Get_Address (Handle : C_Buffer_Handle) return System.Address
   is
      use System;
   begin
      if Handle < 0 or else Handle >= C_Buffer_Handle (Pool_Size) then
         return Null_Address;
      end if;

      declare
         Idx  : constant Pool.Pool_Index := Pool.Pool_Index (Handle);
         Desc : constant Buffer_Descriptor := Descriptors (Idx);
      begin
         if not Desc.In_Use then
            return Null_Address;
         end if;

         return Get_Address (Desc);
      end;
   end C_Pool_Get_Address;

   function C_Pool_Get_Size return size_t is
   begin
      return size_t (Packet_Size);
   end C_Pool_Get_Size;

   function C_Pool_Get_Count return size_t is
   begin
      return size_t (Pool_Size);
   end C_Pool_Get_Count;

end Packet_Pool;
