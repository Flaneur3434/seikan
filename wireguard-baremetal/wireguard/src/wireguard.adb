--  Wireguard - Top-level C interface implementation
--
--  All WireGuard protocol intelligence lives here. C only does I/O.
--
--  State:
--    My_Identity, My_Peer  — loaded once in Init
--    HS_State              — ephemeral, wiped after session derivation
--    Tx_Session            — transport session keys (valid after handshake)

with Interfaces;     use Interfaces;
with Interfaces.C;   use Interfaces.C;
with Utils;          use Utils;
with Crypto.KX;
with Handshake;
with Messages;
with Transport;
with WG_Keys;

package body Wireguard is

   use type Handshake.Handshake_Error;

   --  C_bool helpers
   C_True  : constant Interfaces.C.C_bool := Interfaces.C.C_bool'Val (1);
   C_False : constant Interfaces.C.C_bool := Interfaces.C.C_bool'Val (0);

   ---------------------------------------------------------------------------
   --  Package State
   ---------------------------------------------------------------------------

   My_Identity : Handshake.Static_Identity;
   My_Peer     : Handshake.Peer_Config;
   HS_State    : Handshake.Handshake_State := Handshake.Empty_Handshake;
   Tx_Session  : Transport.Session         := Transport.Null_Session;
   Initialized : Boolean := False;

   ---------------------------------------------------------------------------
   --  Init
   ---------------------------------------------------------------------------

   function Init return C_bool is
      Priv_Key    : Crypto.KX.Secret_Key;
      Peer_Pub    : Crypto.KX.Public_Key;
      Key_Pair    : Crypto.KX.Key_Pair;
      Init_Status : Status;
   begin
      --  Load static private key from sdkconfig
      if WG_Keys.Get_Static_Private_Key (Priv_Key) = C_False then
         return C_False;
      end if;

      --  Load peer public key from sdkconfig
      if WG_Keys.Get_Peer_Public_Key (Peer_Pub) = C_False then
         return C_False;
      end if;

      --  Derive our public key from the private key
      Crypto.KX.Derive_Public_Key (Key_Pair.Pub, Priv_Key, Init_Status);
      if not Is_Success (Init_Status) then
         return C_False;
      end if;
      Key_Pair.Sec := Priv_Key;

      --  Initialize our identity
      Handshake.Initialize_Identity (My_Identity, Key_Pair, Init_Status);
      if not Is_Success (Init_Status) then
         return C_False;
      end if;

      --  Initialize peer configuration
      Handshake.Initialize_Peer (My_Peer, Peer_Pub, Init_Status);
      if not Is_Success (Init_Status) then
         return C_False;
      end if;

      --  Initialize packet pools
      Messages.TX_Pool.Initialize;
      Messages.RX_Pool.Initialize;

      --  Reset protocol state
      HS_State   := Handshake.Empty_Handshake;
      Tx_Session := Transport.Null_Session;
      Initialized := True;

      return C_True;
   end Init;

   ---------------------------------------------------------------------------
   --  Helpers: Handshake sub-operations (body-local)
   ---------------------------------------------------------------------------

   --  Handle_Initiation_RX — Responder: process initiation, build response
   function Handle_Initiation_RX
     (RX_Handle : in out Messages.RX_Buffer_Handle;
      RX_Length : Messages.Packet_Length;
      TX_Buf    : access System.Address;
      TX_Len    : access Unsigned_16) return WG_Action
   is
      HS_Err      : Handshake.Handshake_Error;
      Resp_Result : Handshake.Response_Result;
      TX_Handle   : Messages.Buffer_Handle;
      TX_Ref      : Messages.Buffer_Ref;
      Sess_Status : Status;
   begin
      --  Verify minimum length
      if RX_Length < Unsigned_16 (Messages.Handshake_Init_Size) then
         Messages.RX_Pool.Free (RX_Handle);
         return Action_Error;
      end if;

      --  Process initiation directly from RX buffer (zero-copy)
      declare
         RX_View : constant Messages.RX_Buffer_View :=
           Messages.RX_Pool.Borrow (RX_Handle);
         Msg : Messages.Message_Handshake_Initiation
         with Import, Address => RX_View.Buf_Ptr.Data'Address;
      begin
         Handshake.Process_Initiation (Msg, HS_State, My_Identity, HS_Err);
      end;

      --  Done with RX buffer
      Messages.RX_Pool.Free (RX_Handle);

      if HS_Err /= Handshake.HS_OK then
         return Action_Error;
      end if;

      --  Allocate TX buffer for response
      Messages.TX_Pool.Allocate (TX_Handle);
      if Messages.TX_Pool.Is_Null (TX_Handle) then
         return Action_Error;
      end if;

      --  Build response directly in TX buffer (zero-copy)
      Messages.TX_Pool.Borrow_Mut (TX_Handle, TX_Ref);
      declare
         Resp : Messages.Message_Handshake_Response
         with Import, Address => TX_Ref.Buf_Ptr.Data'Address;
      begin
         Handshake.Create_Response
           (Resp, HS_State, My_Identity, Resp_Result);
      end;

      if not Resp_Result.Success then
         Messages.TX_Pool.Return_Ref (TX_Handle, TX_Ref);
         Messages.TX_Pool.Free (TX_Handle);
         return Action_Error;
      end if;

      TX_Ref.Buf_Ptr.Len := Unsigned_16 (Resp_Result.Length);
      Messages.TX_Pool.Return_Ref (TX_Handle, TX_Ref);

      --  Responder derives transport keys immediately after Create_Response
      --  (has all the Noise material; per WireGuard spec §5.4.4)
      Transport.Init_Session (Tx_Session, HS_State, Sess_Status);
      if not Is_Success (Sess_Status) then
         Messages.TX_Pool.Free (TX_Handle);
         return Action_Error;
      end if;

      --  Release TX buffer to C for transmission
      Messages.Release_TX_To_C
        (TX_Handle, Messages.Packet_Length (Resp_Result.Length), TX_Buf.all);
      TX_Len.all := Unsigned_16 (Resp_Result.Length);
      return Action_Send_Response;
   end Handle_Initiation_RX;

   --  Handle_Response_RX — Initiator: process response, derive session
   function Handle_Response_RX
     (RX_Handle : in out Messages.RX_Buffer_Handle;
      RX_Length : Messages.Packet_Length) return WG_Action
   is
      HS_Err      : Handshake.Handshake_Error;
      Sess_Status : Status;
   begin
      --  Verify minimum length
      if RX_Length < Unsigned_16 (Messages.Handshake_Response_Size) then
         Messages.RX_Pool.Free (RX_Handle);
         return Action_Error;
      end if;

      --  Process response directly from RX buffer (zero-copy)
      declare
         RX_View : constant Messages.RX_Buffer_View :=
           Messages.RX_Pool.Borrow (RX_Handle);
         Msg : Messages.Message_Handshake_Response
         with Import, Address => RX_View.Buf_Ptr.Data'Address;
      begin
         Handshake.Process_Response
           (Msg, HS_State, My_Identity, My_Peer, HS_Err);
      end;

      --  Done with RX buffer
      Messages.RX_Pool.Free (RX_Handle);

      if HS_Err /= Handshake.HS_OK then
         return Action_Error;
      end if;

      --  Initiator derives transport keys after Process_Response
      --  HS_State.Kind = State_Established at this point
      Transport.Init_Session (Tx_Session, HS_State, Sess_Status);
      if not Is_Success (Sess_Status) then
         return Action_Error;
      end if;

      return Action_None;
   end Handle_Response_RX;

   --  Handle_Transport_RX — Decrypt transport data in-place
   function Handle_Transport_RX
     (RX_Handle : in out Messages.RX_Buffer_Handle;
      RX_Length : Messages.Packet_Length) return WG_Action
   is
      PT_Len  : Unsigned_16;
      Counter : Unsigned_64;
      Decrypt_Result : Status;
   begin
      if not Tx_Session.Valid then
         Messages.RX_Pool.Free (RX_Handle);
         return Action_Error;
      end if;

      --  Decrypt in-place directly in the RX pool buffer
      declare
         RX_Ref : Messages.RX_Buffer_Ref;
      begin
         Messages.RX_Pool.Borrow_Mut (RX_Handle, RX_Ref);

         declare
            --  Overlay a Byte_Array on the Packet_Buffer data region
            Pkt : Byte_Array (0 .. Natural (RX_Length) - 1)
            with Import, Address => RX_Ref.Buf_Ptr.Data'Address;
         begin
            Transport.Decrypt_Packet
              (S       => Tx_Session,
               Packet  => Pkt,
               Length  => PT_Len,
               Counter => Counter,
               Result  => Decrypt_Result);
         end;

         Messages.RX_Pool.Return_Ref (RX_Handle, RX_Ref);
      end;

      Messages.RX_Pool.Free (RX_Handle);

      --  TODO: deliver plaintext to TUN/IP stack
      --  For now: Action_None (decrypted and discarded)
      if Is_Success (Decrypt_Result) then
         return Action_None;
      else
         return Action_Error;
      end if;
   end Handle_Transport_RX;

   ---------------------------------------------------------------------------
   --  Receive — Main dispatch
   ---------------------------------------------------------------------------

   function Receive
     (RX_Buf : System.Address;
      TX_Buf : access System.Address;
      TX_Len : access Unsigned_16) return WG_Action
   is
      use System;

      RX_Handle : Messages.RX_Buffer_Handle;
      RX_Length : Messages.Packet_Length;
   begin
      TX_Buf.all := Null_Address;
      TX_Len.all := 0;

      if not Initialized then
         return Action_Error;
      end if;

      --  Take ownership of the RX buffer from C
      Messages.Acquire_RX_From_C (RX_Buf, RX_Handle, RX_Length);

      if Messages.RX_Pool.Is_Null (RX_Handle) then
         return Action_Error;
      end if;

      --  Need at least 1 byte for the message type
      if RX_Length = 0 then
         Messages.RX_Pool.Free (RX_Handle);
         return Action_Error;
      end if;

      --  Peek at message type (first byte) via read-only borrow
      declare
         RX_View  : constant Messages.RX_Buffer_View :=
           Messages.RX_Pool.Borrow (RX_Handle);
         Msg_Kind : constant Messages.Message_Kind :=
           Messages.Get_Message_Kind (RX_View.Buf_Ptr.Data (0));
      begin
         case Msg_Kind is
            when Messages.Kind_Handshake_Initiation =>
               return Handle_Initiation_RX
                 (RX_Handle, RX_Length, TX_Buf, TX_Len);

            when Messages.Kind_Handshake_Response =>
               return Handle_Response_RX (RX_Handle, RX_Length);

            when Messages.Kind_Transport_Data =>
               return Handle_Transport_RX (RX_Handle, RX_Length);

            when Messages.Kind_Cookie_Reply | Messages.Kind_Unknown =>
               Messages.RX_Pool.Free (RX_Handle);
               return Action_Error;
         end case;
      end;
   end Receive;

   ---------------------------------------------------------------------------
   --  Create_Initiation — ESP32-initiated handshake
   ---------------------------------------------------------------------------

   function Create_Initiation
     (Out_Len : access Unsigned_16) return System.Address
   is
      use System;

      Result : Handshake.Initiation_Result;
      Handle : Messages.Buffer_Handle;
      Ref    : Messages.Buffer_Ref;
      Addr   : System.Address;
   begin
      Out_Len.all := 0;

      if not Initialized then
         return Null_Address;
      end if;

      --  Allocate a TX pool buffer
      Messages.TX_Pool.Allocate (Handle);
      if Messages.TX_Pool.Is_Null (Handle) then
         return Null_Address;
      end if;

      --  Build initiation directly in TX buffer (zero-copy)
      Messages.TX_Pool.Borrow_Mut (Handle, Ref);
      declare
         Msg : Messages.Message_Handshake_Initiation
         with Import, Address => Ref.Buf_Ptr.Data'Address;
      begin
         Handshake.Create_Initiation
           (Msg, HS_State, My_Identity, My_Peer, Result);
      end;

      if not Result.Success then
         Messages.TX_Pool.Return_Ref (Handle, Ref);
         Messages.TX_Pool.Free (Handle);
         return Null_Address;
      end if;

      Ref.Buf_Ptr.Len := Unsigned_16 (Result.Length);
      Messages.TX_Pool.Return_Ref (Handle, Ref);

      --  Release to C layer for transmission
      Messages.Release_TX_To_C
        (Handle, Messages.Packet_Length (Result.Length), Addr);

      Out_Len.all := Unsigned_16 (Result.Length);
      return Addr;
   end Create_Initiation;

end Wireguard;
