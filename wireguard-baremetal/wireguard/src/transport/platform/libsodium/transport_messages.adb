--  Transport_Messages body - MAC1 prefix extraction functions (libsodium)

package body Transport_Messages
  with SPARK_Mode => On
is

   function To_Mac1_Prefix
     (Msg : Message_Handshake_Initiation) return Initiation_Mac1_Prefix_Bytes
   is
      Result : Initiation_Mac1_Prefix_Bytes;
   begin
      Result (0)        := Msg.Msg_Type;
      Result (1 .. 3)   := Msg.Reserved;
      Result (4 .. 7)   := Msg.Sender;
      Result (8 .. 39)  := Byte_Array (Msg.Ephemeral);
      Result (40 .. 87) := Msg.Encrypted_Static;
      Result (88 .. 115) := Msg.Encrypted_Timestamp;
      return Result;
   end To_Mac1_Prefix;

   function To_Mac1_Prefix
     (Msg : Message_Handshake_Response) return Response_Mac1_Prefix_Bytes
   is
      Result : Response_Mac1_Prefix_Bytes;
   begin
      Result (0)        := Msg.Msg_Type;
      Result (1 .. 3)   := Msg.Reserved;
      Result (4 .. 7)   := Msg.Sender;
      Result (8 .. 11)  := Msg.Receiver;
      Result (12 .. 43) := Byte_Array (Msg.Ephemeral);
      Result (44 .. 59) := Msg.Encrypted_Empty;
      return Result;
   end To_Mac1_Prefix;

end Transport_Messages;
