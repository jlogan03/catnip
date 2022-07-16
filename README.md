# catnip

A no-std, panic-never, heapless, minimally-featured UDP/IP stack for bare-metal.
Intended for high-speed, fixed-time data acquisition and controls on 
physically-secured local networks. 

This crate currently relies on the nightly channel, and as a result, may break regularly
until the required features stabilize.

Makes use of const generic expressions to provide flexibility in, 
and guaranteed correctness of, lengths of headers and data segments without
dynamic allocation.

This library is under active development; major functionality is yet to 
be implemented and I'm sure some bugs are yet to be found.

# Features 
* Ethernet II frames
* IPV4
* UDP
* ARP
* Optional software-side calculation of checksums

# To-do
* Add UDP psuedo-socket trait w/ arbitrary async send/receive functions
* Move to stable once constants defined in traits become available for parametrizing generics

# License
Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
 
at your option.