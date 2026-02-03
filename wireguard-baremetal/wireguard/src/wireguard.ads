with Transport;

package Wireguard
   with SPARK_Mode => On,
        Elaborate_Body
is
   ---------------------------------------------------------------------------
   --  Packet Pool - Re-exported from Transport
   --
   --  The shared buffer pool is now owned by Transport for C interop.
   --  Re-export here for backward compatibility with existing code.
   ---------------------------------------------------------------------------

   package Packet_Pool renames Transport.Packet_Pool;

   --  Re-export commonly used types
   subtype Packet_Buffer is Transport.Packet_Buffer;
   subtype Buffer_Handle is Transport.Buffer_Handle;
   subtype Buffer_View is Transport.Buffer_View;
   subtype Buffer_Ref is Transport.Buffer_Ref;

end Wireguard;
