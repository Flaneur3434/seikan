with Transport;

package Wireguard
   with SPARK_Mode => On,
        Elaborate_Body
is
   ---------------------------------------------------------------------------
   --  Packet Pools - Re-exported from Transport
   ---------------------------------------------------------------------------

   package TX_Pool renames Transport.TX_Pool;
   package RX_Pool renames Transport.RX_Pool;

   --  Re-export commonly used types (TX)
   subtype Packet_Buffer is Transport.Packet_Buffer;
   subtype Buffer_Handle is Transport.Buffer_Handle;
   subtype Buffer_View is Transport.Buffer_View;
   subtype Buffer_Ref is Transport.Buffer_Ref;

   --  Re-export RX types
   subtype RX_Buffer_Handle is Transport.RX_Buffer_Handle;
   subtype RX_Buffer_View is Transport.RX_Buffer_View;
   subtype RX_Buffer_Ref is Transport.RX_Buffer_Ref;

end Wireguard;
