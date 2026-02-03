--  Packet_Pool - C FFI Implementation
--
--  Handle = buffer address (void*). Simple and direct.
--  WARNING: Caller must follow ownership rules - no aliasing, no double-free.

package body Packet_Pool
   with SPARK_Mode => Off
is

   procedure C_Pool_Init is
   begin
      Transport.Packet_Pool.Initialize;
   end C_Pool_Init;

   function C_Pool_Allocate return System.Address is
   begin
      return Transport.Packet_Pool.C_Allocate;
   end C_Pool_Allocate;

   procedure C_Pool_Free (Addr : System.Address) is
   begin
      Transport.Packet_Pool.C_Free (Addr);
   end C_Pool_Free;

   function C_Pool_Get_Size return size_t is
   begin
      return size_t (Packet_Size);
   end C_Pool_Get_Size;

   function C_Pool_Get_Count return size_t is
   begin
      return size_t (Pool_Size);
   end C_Pool_Get_Count;

end Packet_Pool;
