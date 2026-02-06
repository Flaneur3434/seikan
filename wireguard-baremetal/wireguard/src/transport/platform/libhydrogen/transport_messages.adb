--  Transport_Messages body - MAC1 prefix extraction functions (libhydrogen)

package body Transport_Messages
  with SPARK_Mode => On
is

   function To_Mac1_Prefix
     (Msg : Message_Handshake_Initiation) return Initiation_Mac1_Prefix_Bytes
   is
      Result : Initiation_Mac1_Prefix_Bytes;
      Offset : Natural := 0;
   begin
      Result (Offset) := Msg.Msg_Type;
      Offset := Offset + 1;

      Result (Offset .. Offset + 2) := Msg.Reserved;
      Offset := Offset + 3;

      Result (Offset .. Offset + 3) := Msg.Sender;
      Offset := Offset + 4;

      Result (Offset .. Offset + Key_Size - 1) :=
        Byte_Array (Msg.Ephemeral);
      Offset := Offset + Key_Size;

      Result (Offset .. Offset + Encrypted_Static_Size - 1) :=
        Msg.Encrypted_Static;
      Offset := Offset + Encrypted_Static_Size;

      Result (Offset .. Offset + Encrypted_Timestamp_Size - 1) :=
        Msg.Encrypted_Timestamp;

      return Result;
   end To_Mac1_Prefix;

   function To_Mac1_Prefix
     (Msg : Message_Handshake_Response) return Response_Mac1_Prefix_Bytes
   is
      Result : Response_Mac1_Prefix_Bytes;
      Offset : Natural := 0;
   begin
      Result (Offset) := Msg.Msg_Type;
      Offset := Offset + 1;

      Result (Offset .. Offset + 2) := Msg.Reserved;
      Offset := Offset + 3;

      Result (Offset .. Offset + 3) := Msg.Sender;
      Offset := Offset + 4;

      Result (Offset .. Offset + 3) := Msg.Receiver;
      Offset := Offset + 4;

      Result (Offset .. Offset + Key_Size - 1) :=
        Byte_Array (Msg.Ephemeral);
      Offset := Offset + Key_Size;

      Result (Offset .. Offset + Encrypted_Empty_Size - 1) :=
        Msg.Encrypted_Empty;

      return Result;
   end To_Mac1_Prefix;

end Transport_Messages;
