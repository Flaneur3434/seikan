with Messages;

package Wireguard
   with SPARK_Mode => On,
        Elaborate_Body
is
   ---------------------------------------------------------------------------
   --  Packet Pools - Re-exported from Messages
   ---------------------------------------------------------------------------

   package TX_Pool renames Messages.TX_Pool;
   package RX_Pool renames Messages.RX_Pool;

   --  Re-export commonly used types (TX)
   subtype Packet_Buffer is Messages.Packet_Buffer;
   subtype Buffer_Handle is Messages.Buffer_Handle;
   subtype Buffer_View is Messages.Buffer_View;
   subtype Buffer_Ref is Messages.Buffer_Ref;

   --  Re-export RX types
   subtype RX_Buffer_Handle is Messages.RX_Buffer_Handle;
   subtype RX_Buffer_View is Messages.RX_Buffer_View;
   subtype RX_Buffer_Ref is Messages.RX_Buffer_Ref;

end Wireguard;
