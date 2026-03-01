--  Peer_Table — Unified peer configuration + routing + endpoint table
--
--  Each peer entry holds:
--    - Static public key (for handshake peer identification)
--    - AllowedIPs list  (cryptokey routing: TX LPM + RX source filter)
--    - Outer endpoint   (mutable: updated on authenticated RX per §6.5)

with Interfaces; use Interfaces;
with Session;
with Utils.Result;
with Crypto.KX;

package Peer_Table
  with SPARK_Mode => On
is

   --------------------------------------------------------------------------
   --  Constants
   --------------------------------------------------------------------------

   Max_Allowed_IPs : constant := 2;

   --------------------------------------------------------------------------
   --  Types
   --------------------------------------------------------------------------

   --  IPv4 prefix for AllowedIPs matching
   type IP_Prefix is record
      Addr       : Unsigned_32;          --  Network byte order
      Prefix_Len : Natural range 0 .. 32;
   end record;

   type Allowed_IP_Array is
     array (1 .. Max_Allowed_IPs) of IP_Prefix;

   --  Outer UDP endpoint (mutable at runtime)
   type Endpoint is record
      Addr  : Unsigned_32 := 0;  --  IPv4 network byte order
      Port  : Unsigned_16 := 0;  --  Network byte order
      Valid : Boolean     := False;
   end record;

   --------------------------------------------------------------------------
   --  Initialization
   --------------------------------------------------------------------------

   --  Register a peer's static public key.
   --  This is the core of cryptokey routing — maps a public key to a peer.
   procedure Set_Public_Key
     (Peer : Session.Peer_Index;
      Key  : Crypto.KX.Public_Key);

   subtype AIP_Count is Natural range 0 .. Max_Allowed_IPs;

   --  Register a peer's AllowedIPs (bulk).
   --  Called once at startup for each configured peer.
   --  Count = 0 is valid (peer has no AllowedIPs — no routing, no filter).
   procedure Set_Allowed_IPs
     (Peer  : Session.Peer_Index;
      IPs   : Allowed_IP_Array;
      Count : AIP_Count);

   --------------------------------------------------------------------------
   --  TX routing — Longest Prefix Match
   --------------------------------------------------------------------------

   type Lookup_Err is (No_Match);
   package Lookup_Result is new Utils.Result
     (T => Session.Peer_Index, E => Lookup_Err);

   --  Look up which peer owns a destination IP.
   --  Returns Ok(peer_index) for the longest matching prefix,
   --  or Err(No_Match) if no peer's AllowedIPs covers the address.
   function Lookup_By_IP
     (Dest_IP : Unsigned_32) return Lookup_Result.Result;

   --  Look up a peer by its static public key.
   --  Returns Ok(peer_index) if found, Err(No_Match) if no peer has that key.
   function Lookup_By_Key
     (Key : Crypto.KX.Public_Key) return Lookup_Result.Result;

   --------------------------------------------------------------------------
   --  RX source filter — cryptokey routing validation
   --------------------------------------------------------------------------

   type Source_Err is (Rejected);
   package Source_Result is new Utils.Result
     (T => Session.Peer_Index, E => Source_Err);

   --  After decryption, verify the inner source IP is in the
   --  sending peer's AllowedIPs.  Per §4: prevents a compromised
   --  peer from spoofing addresses outside its AllowedIPs.
   --  Returns Ok(peer) if allowed, Err(Rejected) if not.
   function Check_Source
     (Peer   : Session.Peer_Index;
      Src_IP : Unsigned_32) return Source_Result.Result;

   --------------------------------------------------------------------------
   --  Endpoint management
   --------------------------------------------------------------------------

   --  Update a peer's outer endpoint.
   --  Called after cryptographic authentication (§6.5).
   procedure Update_Endpoint
     (Peer : Session.Peer_Index;
      Addr : Unsigned_32;
      Port : Unsigned_16);

   --  Retrieve a peer's last known outer endpoint.
   procedure Get_Endpoint
     (Peer  : Session.Peer_Index;
      EP    : out Endpoint);

end Peer_Table;
