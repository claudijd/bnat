#bnat-scan-fast - A tool to generate an extremely high rate of syn traffic in
#  conjunction with a separate packet capture to find bnat instances
#
#Jonathan Claudius
#Copyright (C) 2011 Trustwave
#
#This program is free software: you can redistribute it and/or modify it under
#the terms of the GNU General Public License as published by the Free Software
#Foundation, either version 3 of the License, or (at your option) any later
#version.
#
#This program is distributed in the hope that it will be useful, but WITHOUT
#ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
#FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License along with
#this program. If not, see <http://www.gnu.org/licenses/>.

require 'rubygems'
require 'packetfu'
require 'netaddr'

#Set specific port we are going scan for
port = 80

#Spit version
puts "\nbnat-scan-fast v0.1\n"

#Spit usage
def usage
  puts "\nUsage: ruby bnat-scan-fast.rb <file of ipaddresses OR CIDR netblocks>\n"
  puts "\nWARNING: You need to setup a separate packet capture to catch responses\n"
  exit
end

#Verify we only have one arg || usage
if ARGV.length != 1
  usage()
end

#Get the things set that we don't wantch to touch during run time
config = PacketFu::Utils.whoami?()
#use this if you want an explicit scan interface
#config = PacketFu::Utils.whoami?(:iface=>"eth0") 
$tcp_pkt = PacketFu::TCPPacket.new(
  :config=>config,
  :timeout=> 0.1,
  :flavor=>"Windows"
)
$tcp_pkt.tcp_flags.syn=1
$tcp_pkt.tcp_win=14600
$tcp_pkt.tcp_options="MSS:1460,SACKOK,TS:3853;0,NOP,WS:5" 
$tcp_pkt.tcp_dst=port

#Keep Track of the number of IP's we scan
$ips = 0

#Scan a Single IP
def scanip(target)
  #Set Target IP
  $tcp_pkt.ip_daddr=target
  
  #Ruby Scan Command
  scan=Thread.new do
    $tcp_pkt.tcp_src=rand(64511)+1024
    $tcp_pkt.tcp_seq=rand(64511)+1024
    $tcp_pkt.recalc
    $tcp_pkt.to_w
  end
end

#Scan a CIDR Range
def scanrange(range)
  #Clean off garbage characters from the file
  range.gsub!("\s","")
  range.gsub!("\n","")
  
  #Define CIDR Netblock
  cidr4 = NetAddr::CIDR.create(range)
  
  #Determine start and end IP of range
  start = NetAddr::CIDR.create(cidr4.first)
  fin = NetAddr::CIDR.create(cidr4.last)
  $ips += cidr4.size
  
  #Scan Range
  (start..fin).each {|addr| 
    scanip(addr.ip)
  }
end

#Load Ranges From File
ranges = File.new(ARGV[0],"r")

#Mark Start Scan Time
start_time = Time.now.utc
puts "Scan start time: #{start_time}"

#Scan Each Range
ranges.each do |range|
  scanrange(range)  
end

#Mark Scan Completion and Run Time in Seconds
puts "\nBNAT Scanned #{$ips} IPs in #{Time.now - start_time}s"
puts "\n"