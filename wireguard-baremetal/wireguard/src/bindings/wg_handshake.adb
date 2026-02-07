--  WG_Handshake - C-callable WireGuard Handshake API (body)
--
--  Zero-copy implementation: message records are overlaid directly on pool
--  buffer memory via address clauses. No intermediate copies.
--
--  TX path:  Allocate → Borrow_Mut → overlay message record on Data →
--            call Create_* → set Len → Return_Ref → Release_To_C
--  RX path:  Acquire_From_C → Borrow → overlay message record on Data →
--            call Process_* → Free

with Interfaces; use Interfaces;
with Utils;      use Utils;
with Crypto.KX;
with Handshake;
with Messages;
with WG_Keys;

package body WG_Handshake is

   use type Handshake.Handshake_Error;

   --  C_bool conversion helpers
   C_False : constant Interfaces.C.C_bool := Interfaces.C.C_bool (False);
   C_True  : constant Interfaces.C.C_bool := Interfaces.C.C_bool (True);

   ---------------------
   --  Package State
   ---------------------

   My_Identity : Handshake.Static_Identity;
   My_Peer     : Handshake.Peer_Config;
   HS_State    : Handshake.Handshake_State := Handshake.Empty_Handshake;
   Initialized : Boolean := False;

   ---------------------
   --  Init
   ---------------------

   function Init return Interfaces.C.C_bool is
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

      --  Reset handshake state
      HS_State := Handshake.Empty_Handshake;
      Initialized := True;

      return C_True;
   end Init;

   ---------------------
   --  Create_Initiation  (Initiator TX)
   --
   --  Zero-copy: overlay Message_Handshake_Initiation on buffer Data,
   --  Create_Initiation writes directly into pool memory.
   ---------------------

   function Create_Initiation
     (Out_Len : access Interfaces.Unsigned_16) return System.Address
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

      --  Borrow mutably and build message directly in buffer
      Messages.TX_Pool.Borrow_Mut (Handle, Ref);
      declare
         --  Overlay message record on buffer data (zero-copy)
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

   ---------------------
   --  Handle_Initiation  (Responder RX → TX)
   --
   --  Zero-copy: overlay initiation record on RX buffer for reading,
   --  overlay response record on TX buffer for writing.
   ---------------------

   function Handle_Initiation
     (RX_Buf : System.Address; Out_Len : access Interfaces.Unsigned_16)
      return System.Address
   is
      use System;

      RX_Handle   : Messages.RX_Buffer_Handle;
      RX_Length   : Messages.Packet_Length;
      RX_View     : Messages.RX_Buffer_View;
      HS_Err      : Handshake.Handshake_Error;
      Resp_Result : Handshake.Response_Result;
      TX_Handle   : Messages.Buffer_Handle;
      TX_Ref      : Messages.Buffer_Ref;
      TX_Addr     : System.Address;
   begin
      Out_Len.all := 0;

      if not Initialized then
         return Null_Address;
      end if;

      --  Acquire the received buffer from RX pool
      Messages.Acquire_RX_From_C (RX_Buf, RX_Handle, RX_Length);

      if Messages.RX_Pool.Is_Null (RX_Handle) then
         return Null_Address;
      end if;

      --  Verify minimum length
      if RX_Length < Unsigned_16 (Messages.Handshake_Init_Size) then
         Messages.RX_Pool.Free (RX_Handle);
         return Null_Address;
      end if;

      --  Read initiation directly from RX buffer (zero-copy)
      RX_View := Messages.RX_Pool.Borrow (RX_Handle);
      declare
         Msg : Messages.Message_Handshake_Initiation
         with Import, Address => RX_View.Buf_Ptr.Data'Address;
      begin
         Handshake.Process_Initiation (Msg, HS_State, My_Identity, HS_Err);
      end;

      --  Done with RX buffer
      Messages.RX_Pool.Free (RX_Handle);

      if HS_Err /= Handshake.HS_OK then
         return Null_Address;
      end if;

      --  Allocate TX buffer for response
      Messages.TX_Pool.Allocate (TX_Handle);
      if Messages.TX_Pool.Is_Null (TX_Handle) then
         return Null_Address;
      end if;

      --  Build response directly in TX buffer (zero-copy)
      Messages.TX_Pool.Borrow_Mut (TX_Handle, TX_Ref);
      declare
         Resp : Messages.Message_Handshake_Response
         with Import, Address => TX_Ref.Buf_Ptr.Data'Address;
      begin
         Handshake.Create_Response (Resp, HS_State, My_Identity, Resp_Result);
      end;

      if not Resp_Result.Success then
         Messages.TX_Pool.Return_Ref (TX_Handle, TX_Ref);
         Messages.TX_Pool.Free (TX_Handle);
         return Null_Address;
      end if;

      TX_Ref.Buf_Ptr.Len := Unsigned_16 (Resp_Result.Length);
      Messages.TX_Pool.Return_Ref (TX_Handle, TX_Ref);

      --  Release to C for transmission
      Messages.Release_TX_To_C
        (TX_Handle, Messages.Packet_Length (Resp_Result.Length), TX_Addr);

      Out_Len.all := Unsigned_16 (Resp_Result.Length);
      return TX_Addr;
   end Handle_Initiation;

   ---------------------
   --  Handle_Response  (Initiator RX)
   --
   --  Zero-copy: overlay response record on RX buffer for reading.
   ---------------------

   function Handle_Response
     (RX_Buf : System.Address) return Interfaces.C.C_bool
   is
      RX_Handle : Messages.RX_Buffer_Handle;
      RX_Length : Messages.Packet_Length;
      RX_View   : Messages.RX_Buffer_View;
      HS_Err    : Handshake.Handshake_Error;
   begin
      if not Initialized then
         return C_False;
      end if;

      --  Acquire the received buffer from RX pool
      Messages.Acquire_RX_From_C (RX_Buf, RX_Handle, RX_Length);

      if Messages.RX_Pool.Is_Null (RX_Handle) then
         return C_False;
      end if;

      --  Verify minimum length
      if RX_Length < Unsigned_16 (Messages.Handshake_Response_Size) then
         Messages.RX_Pool.Free (RX_Handle);
         return C_False;
      end if;

      --  Process response directly from RX buffer (zero-copy)
      RX_View := Messages.RX_Pool.Borrow (RX_Handle);
      declare
         Msg : Messages.Message_Handshake_Response
         with Import, Address => RX_View.Buf_Ptr.Data'Address;
      begin
         Handshake.Process_Response
           (Msg, HS_State, My_Identity, My_Peer, HS_Err);
      end;

      --  Done with RX buffer
      Messages.RX_Pool.Free (RX_Handle);

      if HS_Err = Handshake.HS_OK then
         return C_True;
      else
         return C_False;
      end if;
   end Handle_Response;

end WG_Handshake;
