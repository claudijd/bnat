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
include PacketFu

$portarray = [22, 23, 80, 443, 445]

puts "\nbnat-scan v0.2\n"

def usage
  puts "\nUsage: ruby bnat-scan.rb <ipaddress OR CIDR netblock>\n"
  puts "\nWARNING: do not initiate any outbound traffic while performing a scan to ensure accurate results\n"
  puts "\nWARNING: your scanning host must be directly connected to the Internet w/o firewall/router/nat service\n\n"
  exit
end

if ARGV.length != 1
  usage()
end

def scanip(target)

synack_hash = Hash.new
synackarray = Array.new

#Start Capture for !IP
pcap = PacketFu::Capture.new(:iface => 'eth0', :start => true, :filter => "tcp and not host #{target} and tcp[13] == 18")

#Ruby Scan Command
scan=Thread.new do
  config = PacketFu::Utils.whoami?(:iface=>"eth0")
  tcp_pkt = PacketFu::TCPPacket.new(:config=>config, :timeout=> 0.1, :flavor=>"Windows")
  tcp_pkt.ip_daddr=target
  tcp_pkt.tcp_flags.syn=1
  tcp_pkt.tcp_win=14600
  tcp_pkt.tcp_options="MSS:1460,SACKOK,TS:3853;0,NOP,WS:5" 
  pbar = ProgressBar.new("#{target}", 5)
  count = 1
  $portarray.each { |x|
    tcp_pkt.tcp_src=rand(64511)+1024
    tcp_pkt.tcp_dst=x
    tcp_pkt.recalc
    tcp_pkt.to_w
    sleep 0.075
    tcp_pkt.to_w
    pbar.set(count)
    count = count + 1
  }
end

#Check for stray SYN/ACK Responses
analyze=Thread.new do
  loop {
    pcap.stream.each {
      |pkt| packet = PacketFu::Packet.parse(pkt)
		synack_hash = { "ip" => packet.ip_saddr.to_s, "port" => packet.tcp_sport.to_s}
		synackarray.push(synack_hash)
    }  
  }
end

#Wait until scan is complete before continuing
scan.join
sleep 0.05
analyze.terminate

#Clean up duplicate responses received
synackarray = synackarray.uniq

#Print BNAT Pairs to SYSOUT
synackarray.each do |synack|
  puts "\n[BNAT Response] Request: #{target} Response: #{synack["ip"]} Port: #{synack["port"]}"
end

end

#scanip(ARGV[0])

cidr4 = NetAddr::CIDR.create(ARGV[0])
puts "Scan scope has #{cidr4.size} IP's\n\n"
start = NetAddr::CIDR.create(cidr4.first)
fin = NetAddr::CIDR.create(cidr4.last)
puts "Performing BNAT scan...\n"
(start..fin).each {|addr| 
  #puts "\n"
  scanip(addr.ip)
}
puts "\nCompleted BNAT scan"
puts "\n"

