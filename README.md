# BNAT

[![Build Status](https://secure.travis-ci.org/claudijd/bnat.png)](http://travis-ci.org/claudijd/bnat)

BNAT (Broken NAT) is namely defined as IP communication that is being improperly nat'd to create an inoperable communication channel. A common example of BNAT is found in asymmetric routing where we (intentionally or unintentionally) create a logical layer 3 loop in a TCP/IP session between a client and a server. This is commonly found in complex routing scenarios or situations where mistakes are "corrected" to make something work without understanding or caring about the actual flow of traffic.

## Very Basic Example

```
.1 ----SYN-----> .2 (.1 is the client and starts a session w/ a syn to .2)
.1 <--SYN/ACK--- .3 (.3 responds to .1 with the syn/ack)
.1 ----RST-----> .3 (.1 responds to .3 with a rst)
```

## Why Does BNAT Matter?

BNAT effectively hides TCP ports from being identified by modern TCP clients and port scanning utilities like NMAP. With the right tools, you can identify ports that would otherwise be considered as closed/filtered which can be converted into legitimate open ports. This opens the door for traditional exploitation vectors in a service that was previously unreachable.

## BNAT Presentations

- [**BNAT Hijacking: Repairing Broken Communication Channels**](https://speakerdeck.com/claudijd/bnat-hijacking-repairing-broken-communication-channels)

## BNAT Videos

- [**BNAT-Scan compared to NMAP -sS Scan**](http://www.youtube.com/watch?v=8Um1cJswCeM)
- [**BNAT-Router handling BNAT'd SSH Session**](http://www.youtube.com/watch?v=C8zv10VHyUg)
- [**Using Metaploit's BNAT auxmod's to exploit Tomcat**](http://www.youtube.com/watch?v=FS_cg1PVhkI)

## Blog Posts

- [**Metasploit Blog - A Tale From Defcon and the Fun of BNAT**](https://community.rapid7.com/community/metasploit/blog/2011/08/26/a-tale-from-defcon-and-the-fun-of-bnat)
- [**Spiderlabs Blog - Advanced BNAT in the Wild**](http://blog.spiderlabs.com/2011/09/advanced-bnat-broken-network-address-translation-in-the-wild.html)

## Setup

TODO

## Rubies Supported

TODO

## Contributing

If you are interested in contributing to this project, please see [CONTRIBUTING.md](https://github.com/claudijd/bnat/blob/master/CONTRIBUTING.md)

## Credits

TODO
