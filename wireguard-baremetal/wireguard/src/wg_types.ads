--  WG_Types - SPARK-Visible WireGuard Shared Types
--
--  Holds types that both the SPARK-proven protocol core and the
--  C-facing shim need.  Kept in its own package so it can be
--  SPARK_Mode => On while Wireguard stays SPARK_Mode => Off.

package WG_Types
  with SPARK_Mode => On
is

   ---------------------------------------------------------------------------
   --  Action - What C should do after wg_receive
   ---------------------------------------------------------------------------

   type WG_Action is
     (Action_None,            --  Nothing to do
      Action_Send_Response,   --  Call wg_create_response
      RX_Decryption_Success,  --  Decrypted data in pt_out
      Action_Error)           --  Processing failed
   with Convention => C;

   for WG_Action use
     (Action_None           => 0,
      Action_Send_Response  => 1,
      RX_Decryption_Success => 2,
      Action_Error          => 3);

end WG_Types;
