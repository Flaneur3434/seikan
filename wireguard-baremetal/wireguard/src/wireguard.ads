with System;
with Utils;
with Utils.Memory_Pool;

package Wireguard
   with SPARK_Mode => On,
        Elaborate_Body
is
   ---------------------------------------------------------------------------
   --  Packet Pool - Shared buffer pool for network packets
   --
   --  Used by both Ada code and C FFI. Instantiated here at the top level
   --  so all modules can access it.
   ---------------------------------------------------------------------------

   Packet_Size : constant := Utils.Max_Packet_Size;
   Pool_Size   : constant := 8;

   package Packet_Pool is new Utils.Memory_Pool
     (Packet_Size => Packet_Size,
      Pool_Size   => Pool_Size);

   --  Re-export commonly used types
   subtype Packet_Buffer is Packet_Pool.Packet_Buffer;
   subtype Buffer_Handle is Packet_Pool.Buffer_Handle;
   subtype Buffer_View is Packet_Pool.Buffer_View;
   subtype Buffer_Ref is Packet_Pool.Buffer_Ref;

end Wireguard;
