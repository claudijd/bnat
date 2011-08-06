# What is BNAT?

BNAT (Broken NAT) is namely defined as IP communication that is being improperly nat'd to create an inoperable communications channel.  A common example of BNAT is found in asymmetric routing where we (intentially or unintentionally) create a logical layer 3 loop in a TCP/IP session between a client and a server. This is commonly found in complex routing scenarios or situations where mistakes are "corrected" to make something work without understanding or caring about the actual flow of traffic.

## Very Basic Example...

    .1 ----SYN----> .2 (.1 is the client and starts a session w/ a syn to .2)
    .1 <--SYN/ACK-- .3 (.3 responds to .1 with the syn/ack)
	
# Why does BNAT matter?

BNAT effectively hides TCP ports from being identified by modern TCP clients and port scanning utilities like NMAP.  With the right tools, you can identify ports that would otherwise be considered as closed/filtered which can be converted into legitimate open ports.

# Check out my Presentation

DEFCON Skytalks VI: http://www.slideshare.net/claudijd/dc-skytalk-bnat-hijacking-repairing-broken-communication-channels

# Video Demo's

BNAT-Scan: http://www.youtube.com/watch?v=8Um1cJswCeM

BNAT-Router: http://www.youtube.com/watch?v=C8zv10VHyUg

# Setup on Ubuntu 10.04 LTS (lucid) w/ Ruby 1.9.2-p180 #

## Prep the System ##

    sudo aptitude update
    sudo aptitude -y install build-essential git-core curl tcpdump libpcap-dev libpcap-ruby
    bash < <( curl https://rvm.beginrescueend.com/releases/rvm-install-head )
    echo '[[ -s "$HOME/.rvm/scripts/rvm" ]] && source "$HOME/.rvm/scripts/rvm"' >> ~/.bashrc
    #close exiting terminal, start new one
    rvm notes
    #install 'rvm notes' output of recommended apt-get packages
    #the next step might take some time, be patient
    rvm install 1.9.2-p180
    rvm 1.9.2-p180
    rvm --default use 1.9.2-p180
    rvm gem install pcaprub packetfu netaddr progressbar

## Check out BNAT Scan

    git clone https://github.com/claudijd/BNAT-Suite.git