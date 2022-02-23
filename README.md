# catnip

A no-std, heapless, minimally-featured UDP/IP stack for bare-metal.
Intended for high-speed, realtime data acquisition and controls on 
physically-secured local networks.

Makes extensive use of const generic expressions to provide flexibility in, 
and guaranteed correctness of, lengths of headers and data segments without
dynamic allocation.

This library is under active development; major functionality is yet to 
be implemented and I'm sure some bugs are yet to be found.

# To-do

* Add DHCP for autonegotiation of IP address
* Add PTP functionality
* Add VLAN functionality
