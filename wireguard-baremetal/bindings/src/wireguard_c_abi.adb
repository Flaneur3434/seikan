--  WireGuard C ABI Implementation

package body Wireguard_C_ABI is

   procedure Receive_Bytes
      (Buf : System.Address;
       Len : Natural) is
   begin
      --  TODO: Implement
      --  1. Convert System.Address to Ada byte array
      --  2. Call Wireguard.Receive_Packet (or similar)
      --  3. Handle state machine updates
      null;
   end Receive_Bytes;

   function Prepare_TX
      (Out_Buf : System.Address;
       Max_Len : Natural)
       return Natural is
   begin
      --  TODO: Implement
      --  1. Call Wireguard.Prepare_TX (or similar)
      --  2. Convert Ada packet to bytes at Out_Buf
      --  3. Return number of bytes written
      return 0;
   end Prepare_TX;

end Wireguard_C_ABI;
