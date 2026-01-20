--  Net - Network types for WireGuard protocol
--
--  Types used by Ada protocol logic to represent network endpoints.
--  Actual I/O is handled by C platform layer.

with Interfaces;

package Net
  with SPARK_Mode => On
is
   use Interfaces;

   subtype Byte is Unsigned_8;
   type Byte_Array is array (Natural range <>) of Byte;

   --  IPv4 address (4 bytes, network byte order)
   type IPv4_Address is array (0 .. 3) of Byte;

   --  IPv6 address (16 bytes, network byte order)
   type IPv6_Address is array (0 .. 15) of Byte;

   --  UDP port number (host byte order)
   subtype Port_Number is Unsigned_16;

   --  IPv4 endpoint (address + port)
   type IPv4_Endpoint is record
      Addr : IPv4_Address;
      Port : Port_Number;
   end record;

   --  IPv6 endpoint (address + port)
   type IPv6_Endpoint is record
      Addr : IPv6_Address;
      Port : Port_Number;
   end record;

   --  Special addresses
   Any_IPv4 : constant IPv4_Address := (0, 0, 0, 0);
   Any_IPv6 : constant IPv6_Address := (others => 0);

   --  Loopback addresses
   Loopback_IPv4 : constant IPv4_Address := (127, 0, 0, 1);

end Net;
