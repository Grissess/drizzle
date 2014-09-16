drizzle
=======

Drizzle is a small UDP-based network peer that attempts to establish a densely-linked complete graph of direct connections between nodes that may be behind arbitrarily many NAT firewalls.

Drizzle attempts to create a complete graph of **direct** "connections" (which are little more than NAT states to any intervening firewalls) over UDP, up to a configurable maximum of connections (on `DPeer` in `netlayer`; more comprehensive configuration will hopefully come later).

At present, Drizzle does not support cryptography on its network layer, though this would form an excellent place to implement it. The present source tree contains a mess of half-integrated cryptography; the most pressing issue is setting up a distributed PKI that would be compatible with the Drizzle ideology of having no master nodes.

To run a demonstration, do either of the following:

    python netlayer.py [<port> [<host> [<host> [...]]]]
    python qtnt.py [<port> [<host> [<host> [...]]]]
    
The former uses only a command line, the latter runs a Qt interface (and requires PyQt4). Both accept the same arguments:

* <port> is the port to listen on; if not specified, this defaults to 9652.
* <host> is a host to try to synchronize with. In qtnt, this can be alternatively specified during runtime using a provided entry. Any number of hosts can be provided, including zero (which may be used to set up a server node with no initial connections).
