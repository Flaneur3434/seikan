--  Packet_Pool - C FFI Implementation for RX and TX pools

package body Packet_Pool
   with SPARK_Mode => Off
is

   ---------------------------------------------------------------------------
   --  TX Pool
   ---------------------------------------------------------------------------

   procedure C_TX_Pool_Init is
   begin
      Messages.TX_Pool.Initialize;
   end C_TX_Pool_Init;

   function C_TX_Pool_Allocate return System.Address is
   begin
      return Messages.TX_Pool.C_Allocate;
   end C_TX_Pool_Allocate;

   procedure C_TX_Pool_Free (Addr : System.Address) is
   begin
      Messages.TX_Pool.C_Free (Addr);
   end C_TX_Pool_Free;

   ---------------------------------------------------------------------------
   --  RX Pool
   ---------------------------------------------------------------------------

   procedure C_RX_Pool_Init is
   begin
      Messages.RX_Pool.Initialize;
   end C_RX_Pool_Init;

   function C_RX_Pool_Allocate return System.Address is
   begin
      return Messages.RX_Pool.C_Allocate;
   end C_RX_Pool_Allocate;

   procedure C_RX_Pool_Free (Addr : System.Address) is
   begin
      Messages.RX_Pool.C_Free (Addr);
   end C_RX_Pool_Free;

   ---------------------------------------------------------------------------
   --  Common queries (same for both pools)
   ---------------------------------------------------------------------------

   function C_Pool_Get_Size return size_t is
   begin
      return size_t (Packet_Size);
   end C_Pool_Get_Size;

   function C_Pool_Get_Count return size_t is
   begin
      return size_t (Pool_Size);
   end C_Pool_Get_Count;

end Packet_Pool;
