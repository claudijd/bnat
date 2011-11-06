# What is BNAT?

BNAT (Broken NAT) is namely defined as IP communication that is being improperly nat'd to create an inoperable communication channel.  A common example of BNAT is found in asymmetric routing where we (intentionally or unintentionally) create a logical layer 3 loop in a TCP/IP session between a client and a server. This is commonly found in complex routing scenarios or situations where mistakes are "corrected" to make something work without understanding or caring about the actual flow of traffic.

## Very Basic Example...

    .1 ----SYN-----> .2 (.1 is the client and starts a session w/ a syn to .2)
    .1 <--SYN/ACK--- .3 (.3 responds to .1 with the syn/ack)
    .1 ---RST--> .3 (.1 responds to .3 with a RST)
	
# Why does BNAT matter?

BNAT effectively hides TCP ports from being identified by modern TCP clients and port scanning utilities like NMAP.  With the right tools, you can identify ports that would otherwise be considered as closed/filtered which can be converted into legitimate open ports.

# Check out my Presentation

DEFCON Skytalks: http://www.slideshare.net/claudijd/dc-skytalk-bnat-hijacking-repairing-broken-communication-channels

# Video Demo's

BNAT-Scan: http://www.youtube.com/watch?v=8Um1cJswCeM (BNAT-Scan compared to NMAP -sS Scan)

BNAT-Router: http://www.youtube.com/watch?v=C8zv10VHyUg (BNAT-Router handling BNAT'd SSH Session)

BNAT in Metasploit: http://www.youtube.com/watch?v=FS_cg1PVhkI (Using BNAT msf auxmod's to exploit Tomcat)

# Native Setup on BT5#

## Prep the System ##

    gem install pcaprub packetfu netaddr progressbar
    iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
	
## Check out BNAT-Suite

    git clone https://github.com/claudijd/BNAT-Suite.git
	
# MSF Setup on BT5#

## Prep the System ##

    iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

## Check out BNAT-Suite

    cd /pentest/exploits/framework3/
    svn update
