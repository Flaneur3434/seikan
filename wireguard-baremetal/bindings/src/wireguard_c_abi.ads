--  WireGuard C ABI
--
--  Minimal C API for calling the Ada/SPARK WireGuard core from C code.
--  This is the only interface across the Ada/C boundary.
--
--  Design principles:
--  - C sees only opaque byte buffers and function pointers
--  - No Ada types exposed to C
--  - All state remains in Ada
--  - Calls are non-reentrant (single-threaded C context only)

with System;

package Wireguard_C_ABI is

   --  Receive raw bytes from network interface.
   --
   --  Ada validates packet type, checks replay window, updates state.
   --  C provides only raw bytes; it does not interpret WireGuard protocol.
   --
   --  Args:
   --    buf - pointer to packet bytes (C owns buffer, Ada borrows)
   --    len - packet length in bytes
   procedure Receive_Bytes
      (Buf : System.Address;
       Len : Natural)
      with Convention => C, External_Name => "wg_receive_bytes";

   --  Prepare outgoing packet for transmission.
   --
   --  Ada decides what to send, constructs and encrypts packet.
   --  C only moves bytes to hardware.
   --
   --  Args:
   --    out_buf  - pointer to output buffer (C owns, Ada writes)
   --    max_len  - maximum bytes C can send
   --
   --  Returns:
   --    Number of bytes written to out_buf (0 if nothing to send)
   function Prepare_TX
      (Out_Buf : System.Address;
       Max_Len : Natural)
       return Natural
      with Convention => C, External_Name => "wg_prepare_tx";

   --  TODO: Add as needed
   --  - initialization
   --  - configuration (peer list, keys)
   --  - status queries
   --
   --  Keep the interface minimal. Avoid exposing state details.

end Wireguard_C_ABI;
