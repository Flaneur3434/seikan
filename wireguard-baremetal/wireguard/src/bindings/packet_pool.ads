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
   subtype Buffer_Descriptor is Pool.Buffer_Descriptor;

   Null_Descriptor : Buffer_Descriptor renames Pool.Null_Descriptor;

   --  Re-export procedures for Ada code
   procedure Initialize renames Pool.Initialize;
   procedure Allocate (Desc : out Buffer_Descriptor) renames Pool.Allocate;
   procedure Free (Desc : in out Buffer_Descriptor) renames Pool.Free;
   function Get_Buffer (Desc : Buffer_Descriptor) return Packet_Buffer
     renames Pool.Get_Buffer;
   procedure Set_Buffer (Desc : Buffer_Descriptor; Data : Packet_Buffer)
     renames Pool.Set_Buffer;
   function Get_Address (Desc : Buffer_Descriptor) return System.Address
     renames Pool.Get_Address;

   ---------------------------------------------------------------------------
   --  C FFI Types
   ---------------------------------------------------------------------------

   --  C-compatible buffer handle (just the index)
   type C_Buffer_Handle is new int;

   Invalid_Handle : constant C_Buffer_Handle := -1;

   ---------------------------------------------------------------------------
   --  C FFI Functions
   ---------------------------------------------------------------------------

   procedure C_Pool_Init
     with Export,
          Convention    => C,
          External_Name => "packet_pool_init",
          SPARK_Mode    => Off;

   function C_Pool_Allocate return C_Buffer_Handle
     with Export,
          Convention    => C,
          External_Name => "packet_pool_allocate",
          SPARK_Mode    => Off;

   procedure C_Pool_Free (Handle : C_Buffer_Handle)
     with Export,
          Convention    => C,
          External_Name => "packet_pool_free",
          SPARK_Mode    => Off;

   function C_Pool_Get_Address (Handle : C_Buffer_Handle) return System.Address
     with Export,
          Convention    => C,
          External_Name => "packet_pool_get_address",
          SPARK_Mode    => Off;

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
