--  Packet_Pool - C FFI for the shared packet buffer pool
--
--  Provides C-callable interface to Wireguard.Packet_Pool.
--  The pool itself is instantiated in wireguard.ads for use by Ada code.

with System;
with Interfaces.C;
with Wireguard;

package Packet_Pool
   with SPARK_Mode => On
is
   use Interfaces.C;

   --  Re-export pool configuration for C
   Packet_Size : constant := Wireguard.Packet_Size;
   Pool_Size   : constant := Wireguard.Pool_Size;

   ---------------------------------------------------------------------------
   --  C FFI Functions
   --
   --  Returns buffer address (void*)
   --  WARNING: C code must follow ownership rules - no aliasing, no
   --  double-free
   ---------------------------------------------------------------------------

   procedure C_Pool_Init
     with Export,
          Convention    => C,
          External_Name => "packet_pool_init",
          SPARK_Mode    => Off;

   function C_Pool_Allocate return System.Address
     with Export,
          Convention    => C,
          External_Name => "packet_pool_allocate",
          SPARK_Mode    => Off;
   --  Returns buffer address, or NULL if pool exhausted

   procedure C_Pool_Free (Addr : System.Address)
     with Export,
          Convention    => C,
          External_Name => "packet_pool_free",
          SPARK_Mode    => Off;
   --  Free buffer at address. Safe to call with NULL.

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
