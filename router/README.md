Verfied functionalities:

Ping to end servers
Traceroute to end servers
wget to end servers
pings to router's interface
traceroute to router's interface
wget to router's interface
pings to invalid address
traceroute to invalid address
wget to invalid address

Design Decisions:

The case of TTL becoming zero is checked before the condition for no matching prefix. This is because in case the TTL becomes zero in this hop, traceroute should know that packet came from this interface, and in the second hop, error should come. 

An ICMP host unreachable packet is sent incase of a UDP/TCP packet intended to this router. This is actually necessary when a ping request or a traceroute request to this router is made.

The case when ICMP host unreachable is sent after 5 failed ARP requests is verified by temporarily ignoring any ARP replies received on this router and checking whether Host Unreachable is reflected in the ping request.

For any arp request received on the router, the senders ip & mac are cached for efficiency.

Cases Handled:

No matching prefix is found in the routing table
TTL became zero in this hop
ARP reply not received even after 5 requests
For an IP packet intended to this router, either an ICMP echo reply or an ICMP Port Unreachable reply
