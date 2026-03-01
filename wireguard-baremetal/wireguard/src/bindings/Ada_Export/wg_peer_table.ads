--  WG_Peer_Table — C FFI for peer table operations
--
--  Exports Peer_Table operations to C for wg_task.c integration.
--  All peer indices are 1-based (Ada Peer_Index).

with Interfaces;
with Interfaces.C;

package WG_Peer_Table
  with SPARK_Mode => Off
is

   --------------------------------------------------------------------------
   --  Public key configuration
   --------------------------------------------------------------------------

   --  Register a peer's static public key (32 bytes).
   --  Core of cryptokey routing: maps a key to a peer index.
   procedure C_Set_Public_Key
     (Peer : Interfaces.C.unsigned;
      Key  : access Interfaces.Unsigned_8)
   with Export,
        Convention    => C,
        External_Name => "wg_peer_set_public_key";

   --  Look up a peer by its static public key.
   --  Returns 1-based peer index, or 0 if no peer has that key.
   function C_Lookup_By_Key
     (Key : access Interfaces.Unsigned_8)
      return Interfaces.C.unsigned
   with Export,
        Convention    => C,
        External_Name => "wg_peer_lookup_by_key";

   --------------------------------------------------------------------------
   --  AllowedIPs configuration
   --------------------------------------------------------------------------

   --  C-side representation of one AllowedIP prefix.
   type C_IP_Prefix is record
      Addr       : Interfaces.Unsigned_32;  --  Network byte order
      Prefix_Len : Interfaces.C.unsigned;   --  0..32
   end record
     with Convention => C;

   type C_IP_Prefix_Array is
     array (Interfaces.C.unsigned range <>) of aliased C_IP_Prefix
     with Convention => C;

   --  Register a peer's AllowedIPs (bulk).
   --  IPs points to a C array of count entries.
   --  Pass count=0 to clear, or count=1 for a single prefix.
   procedure C_Set_Allowed_IPs
     (Peer  : Interfaces.C.unsigned;
      IPs   : access C_IP_Prefix;
      Count : Interfaces.C.unsigned)
   with Export,
        Convention    => C,
        External_Name => "wg_peer_set_allowed_ips";

   --------------------------------------------------------------------------
   --  TX routing — longest prefix match
   --------------------------------------------------------------------------

   --  Look up which peer owns a destination IP.
   --  Returns 1-based peer index, or 0 if no match.
   function C_Lookup_By_IP
     (Dest_IP : Interfaces.Unsigned_32)
      return Interfaces.C.unsigned
   with Export,
        Convention    => C,
        External_Name => "wg_peer_lookup_by_ip";

   --------------------------------------------------------------------------
   --  RX source filter
   --------------------------------------------------------------------------

   --  Check if an inner source IP is in a peer's AllowedIPs.
   --  Returns non-zero if allowed, 0 if rejected.
   function C_Check_Source
     (Peer   : Interfaces.C.unsigned;
      Src_IP : Interfaces.Unsigned_32)
      return Interfaces.C.unsigned_char
   with Export,
        Convention    => C,
        External_Name => "wg_peer_check_source";

   --------------------------------------------------------------------------
   --  Endpoint management
   --------------------------------------------------------------------------

   --  Update a peer's outer endpoint after authenticated RX.
   procedure C_Update_Endpoint
     (Peer : Interfaces.C.unsigned;
      Addr : Interfaces.Unsigned_32;
      Port : Interfaces.Unsigned_16)
   with Export,
        Convention    => C,
        External_Name => "wg_peer_update_endpoint";

   --  Retrieve a peer's endpoint.
   --  Returns non-zero if valid, 0 if no known endpoint.
   function C_Get_Endpoint
     (Peer     : Interfaces.C.unsigned;
      Out_Addr : access Interfaces.Unsigned_32;
      Out_Port : access Interfaces.Unsigned_16)
      return Interfaces.C.unsigned_char
   with Export,
        Convention    => C,
        External_Name => "wg_peer_get_endpoint";

end WG_Peer_Table;
