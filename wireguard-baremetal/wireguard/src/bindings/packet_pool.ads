--  Packet_Pool - C FFI for RX and TX packet buffer pools
--
--  Provides C-callable interface to Transport.RX_Pool and Transport.TX_Pool.

with System;
with Interfaces.C;
with Transport;

package Packet_Pool
   with SPARK_Mode => On
is
   use Interfaces.C;

   --  Re-export pool configuration for C
   Packet_Size : constant := Transport.Packet_Size;
   Pool_Size   : constant := Transport.Pool_Size;

   ---------------------------------------------------------------------------
   --  TX Pool C FFI
   ---------------------------------------------------------------------------

   procedure C_TX_Pool_Init
     with Export,
          Convention    => C,
          External_Name => "tx_pool_init",
          SPARK_Mode    => Off;

   function C_TX_Pool_Allocate return System.Address
     with Export,
          Convention    => C,
          External_Name => "tx_pool_allocate",
          SPARK_Mode    => Off;

   procedure C_TX_Pool_Free (Addr : System.Address)
     with Export,
          Convention    => C,
          External_Name => "tx_pool_free",
          SPARK_Mode    => Off;

   ---------------------------------------------------------------------------
   --  RX Pool C FFI
   ---------------------------------------------------------------------------

   procedure C_RX_Pool_Init
     with Export,
          Convention    => C,
          External_Name => "rx_pool_init",
          SPARK_Mode    => Off;

   function C_RX_Pool_Allocate return System.Address
     with Export,
          Convention    => C,
          External_Name => "rx_pool_allocate",
          SPARK_Mode    => Off;

   procedure C_RX_Pool_Free (Addr : System.Address)
     with Export,
          Convention    => C,
          External_Name => "rx_pool_free",
          SPARK_Mode    => Off;

   ---------------------------------------------------------------------------
   --  Common queries
   ---------------------------------------------------------------------------

   function C_Pool_Get_Size return size_t
     with Export,
          Convention    => C,
          External_Name => "packet_pool_get_buffer_size",
          SPARK_Mode    => Off;

   function C_Pool_Get_Count return size_t
     with Export,
          Convention    => C,
          External_Name => "packet_pool_get_pool_size",
          SPARK_Mode    => Off;

end Packet_Pool;
