--  Packet_Pool - Concrete Memory Pool Instance with C FFI
--
--  Instantiates the generic memory pool for network packets
--  and provides C-callable interface functions.

with System;
with Interfaces.C;
with Utils;
with Utils.Memory_Pool;

package Packet_Pool
   with SPARK_Mode => On
is
   use Interfaces.C;

   --  Pool configuration
   Packet_Size : constant := Utils.Max_Packet_Size;
   Pool_Size   : constant := 8;

   --  Instantiate the generic memory pool
   package Pool is new Utils.Memory_Pool
     (Packet_Size => Packet_Size,
      Pool_Size   => Pool_Size);

   --  Re-export types for Ada code
   subtype Packet_Buffer is Pool.Packet_Buffer;
   subtype Buffer_Handle is Pool.Buffer_Handle;

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
