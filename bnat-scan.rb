#bnat-scan - A tool to actively detect BNAT by scanning a single IP or CIDR netblock
#Jonathan Claudius
#Copyright (C) 2011 Trustwave
#
#This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#
#This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.

require 'rubygems'
require 'packetfu'
require 'netaddr'
require 'progressbar'

#Define the ports that we are going to test for BNAT
$portarray = [80]

#Array to Store our Findings
$bnatarray = []

#Spit version
puts "\nbnat-scan v0.3\n"

def usage
  puts "\nUsage: ruby bnat-scan.rb <ipaddress OR CIDR netblock>\n"
  puts "\nWARNING: do not initiate any outbound traffic while performing a scan to ensure accurate results\n"
  puts "\nWARNING: your scanning host must be directly connected to the Internet w/o firewall/router/nat service\n\n"
  exit
end

if ARGV.length != 1
  usage()
end

#Get the things set that we don't wantch to touch during run time
$config = PacketFu::Utils.whoami?()
#$config = PacketFu::Utils.whoami?() #use this if you want an explicit scan interface
$tcp_pkt = PacketFu::TCPPacket.new(:config=> $config, :timeout=> 0.1, :flavor=>"Windows")
$tcp_pkt.tcp_flags.syn=1
$tcp_pkt.tcp_win=14600
$tcp_pkt.tcp_options="MSS:1460,SACKOK,TS:3853;0,NOP,WS:5"

def scanip(target)
  
  #Set target IP on packet object
  $tcp_pkt.ip_daddr=target
  
  #Stand up some hash/arrays for tracking purposes
  synack_hash = Hash.new
  synackarray = Array.new
  
  #Start Capture for !IP
  pcap = PacketFu::Capture.new(:iface => $config[:iface], :start => true, :filter => "tcp and not host #{target} and tcp[13] == 18")
  #pcap = PacketFu::Capture.new(:iface => 'eth0', :start => true, :filter => "tcp and host #{target} and tcp[13] == 18") #debug purposes only
  
  #Ruby Scan Command
  scan=Thread.new do
    $portarray.each { |port|
      
      #Don't trust OS to randomize source/seq
      $tcp_pkt.tcp_src=rand(64511)+1024
      $tcp_pkt.tcp_seq=rand(64511)+1024
      
      #Set Destination Port
      $tcp_pkt.tcp_dst=port

      #Recalc out checksums and put it to the wire
      $tcp_pkt.recalc
      $tcp_pkt.to_w
      
      #double tap port
      sleep 0.075
      $tcp_pkt.to_w
    }
  end
  
  #Check for stray SYN/ACK Responses
  analyze=Thread.new do
    loop {
      pcap.stream.each {
	|pkt| packet = PacketFu::Packet.parse(pkt)
	  #For every packet we see we load it into a array of hashes
	  synack_hash = { "ip" => packet.ip_saddr.to_s, "port" => packet.tcp_sport.to_s}
	  synackarray.push(synack_hash)
      }  
    }
  end
  
  #Wait until scan is complete before continuing
  scan.join
  sleep 0.05
  analyze.terminate
  
  #De-duplicate responses received (retrans will occur w/o RST)
  synackarray = synackarray.uniq
  
  #Print BNAT Pairs to STDOUT
  synackarray.each do |synack|
    $bnatarray << "[BNAT Instance] Request: #{target} Response: #{synack["ip"]} Port: #{synack["port"]}"
  end
  
end

#Define CIDR Netblock
cidr4 = NetAddr::CIDR.create(ARGV[0])

#Say how big out scan scope is
puts "Scan scope has #{cidr4.size} IP's\n\n"

#Determine our first and last IP in the range
start = NetAddr::CIDR.create(cidr4.first)
fin = NetAddr::CIDR.create(cidr4.last)

puts "Performing BNAT scan...\n"

#Create a progress bar to display our status
pbar = ProgressBar.new("Scan Progress:", cidr4.size)
(start..fin).each_with_index {|addr,i|
  pbar.set(i)
  scanip(addr.ip)
}

puts "\nCompleted BNAT scan\n"
puts "\nWe found #{$bnatarray.length} instance(s) of BNAT\n"

$bnatarray.each do |b|
  puts "#{b}\n"
end

puts "\n"