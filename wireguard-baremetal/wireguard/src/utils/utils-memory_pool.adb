package body Utils.Memory_Pool
  with SPARK_Mode => Off  --  Body uses access types directly
is
   use System;

   ---------------------------------------------------------------------------
   --  Internal State
   --
   --  Static array of buffers. Handles point directly into this array.
   --  Free_Stack tracks which indices are available.
   ---------------------------------------------------------------------------

   Buffers    : array (Pool_Index) of aliased Packet_Buffer :=
                  (others => (others => 0));
   Free_Stack : array (Pool_Index) of Pool_Index;
   Free_Top   : Integer := -1;  --  -1 means empty

   ---------------------------------------------------------------------------
   --  Ghost Function Bodies
   ---------------------------------------------------------------------------

   function Free_Count return Valid_Count is (Free_Top + 1);

   ---------------------------------------------------------------------------
   --  Pool Operations
   ---------------------------------------------------------------------------

   procedure Initialize is
   begin
      for I in Pool_Index loop
         Buffers (I) := (others => 0);
         Free_Stack (I) := I;
      end loop;
      Free_Top := Pool_Size - 1;
   end Initialize;

   procedure Allocate (Handle : out Buffer_Handle) is
      Idx : Pool_Index;
   begin
      if Free_Top < 0 then
         Handle := null;
         return;
      end if;

      Idx := Free_Stack (Free_Top);
      Free_Top := Free_Top - 1;
      Handle := Buffers (Idx)'Access;
   end Allocate;

   procedure Free (Handle : in out Buffer_Handle) is
   begin
      --  Find index by address comparison
      for I in Pool_Index loop
         if Buffers (I)'Address = Handle.all'Address then
            --  Clear sensitive data
            Handle.all := (others => 0);
            Handle := null;

            Free_Top := Free_Top + 1;
            Free_Stack (Free_Top) := I;
            return;
         end if;
      end loop;
      --  Should never reach here if precondition holds
      Handle := null;
   end Free;

   ---------------------------------------------------------------------------
   --  Buffer Access
   ---------------------------------------------------------------------------

   function Data (Handle : Buffer_Handle) return System.Address is
   begin
      return Handle.all'Address;
   end Data;

   ---------------------------------------------------------------------------
   --  C FFI Operations
   ---------------------------------------------------------------------------

   function C_Allocate return System.Address is
      Idx : Pool_Index;
   begin
      if Free_Top < 0 then
         return Null_Address;
      end if;

      Idx := Free_Stack (Free_Top);
      Free_Top := Free_Top - 1;
      return Buffers (Idx)'Address;
   end C_Allocate;

   procedure C_Free (Addr : System.Address) is
   begin
      if Addr = Null_Address then
         return;
      end if;

      for I in Pool_Index loop
         if Buffers (I)'Address = Addr then
            Buffers (I) := (others => 0);
            Free_Top := Free_Top + 1;
            Free_Stack (Free_Top) := I;
            return;
         end if;
      end loop;
   end C_Free;

end Utils.Memory_Pool;
