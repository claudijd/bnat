#bnat-router - A tool to actively hijack TCP-based BNAT identified by bnat-scan/bnat-pcap
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

puts "\nbnat-router v0.1\n\n"

inint = ARGV[0]
outint = ARGV[2]
clientip = ARGV[1]
serverip = ARGV[3]
bnatip = ARGV[4]

##puts "inint #{inint}"
##puts "outint #{outint}"
##puts "bnatip #{bnatip}"
##puts "clientip #{clientip}"
##puts "serverip #{serverip}"

def usage
  puts "\nUsage: ruby bnat-router.rb <insideint> <clientip> <outsideint> <serverip> <bnatip>"
  puts "Example: ruby bnat-router.rb eth1 192.168.3.2 eth0 1.1.2.1 1.1.2.2\n\n"
  Process.exit
end

if ARGV.length != 5
  usage
end

def arp(target_ip,int)
  $config = PacketFu::Config.new(PacketFu::Utils.ifconfig ":#{int}").config
  arp_pkt = PacketFu::ARPPacket.new(:flavor => "Windows")
  arp_pkt.eth_saddr = arp_pkt.arp_saddr_mac = $config[:eth_saddr]
  arp_pkt.eth_daddr = "ff:ff:ff:ff:ff:ff"
  arp_pkt.arp_daddr_mac = "00:00:00:00:00:00"
  arp_pkt.arp_saddr_ip = $config[:ip_saddr]
  arp_pkt.arp_daddr_ip = target_ip
  cap = PacketFu::Capture.new(:iface => $config[:iface], :start => true, :filter => "arp src #{target_ip} and ether dst #{arp_pkt.eth_saddr}")
  injarp = PacketFu::Inject.new(:iface => $config[:iface])
  injarp.a2w(:array => [arp_pkt.to_s])
  target_mac = nil
  while target_mac.nil?
    if cap.save > 0
      arp_response = PacketFu::Packet.parse(cap.array[0])
      target_mac = arp_response.arp_saddr_mac if arp_response.arp_saddr_ip = target_ip
    end
    sleep 0.1 # Check for a response ten times per second.
  end
  #puts "#{target_ip} is-at #{target_mac}"
  return target_mac
end

clientmac = arp(clientip,inint)
puts "Obtained Client MAC: #{clientmac}"
servermac = arp(serverip,outint)
puts "Obtained Server MAC: #{servermac}"
bnatmac = arp(bnatip,outint)
puts "Obtained BNAT MAC: #{bnatmac}\n\n"

#Create Interface Specific Configs
outconfig = PacketFu::Config.new(PacketFu::Utils.ifconfig ":#{outint}").config
inconfig = PacketFu::Config.new(PacketFu::Utils.ifconfig ":#{inint}").config

#Set Captures for Traffic coming from Outside and from Inside respectively
outpcap = PacketFu::Capture.new( :config => "#{outint}", :start => true, :filter => "tcp and src #{bnatip}" )
puts "Now listening on #{outint}..."
inpcap = PacketFu::Capture.new( :iface => "#{inint}", :start => true, :filter => "tcp and src #{clientip} and dst #{serverip}" )
puts "Now listening on #{inint}...\n\n"

#Start Thread from Outside Processing
fromout=Thread.new do
  loop {
    outpcap.stream.each {
      |pkt| packet = PacketFu::Packet.parse(pkt)
 
      #Build a shell packet that will never hit the wire as a hack to get desired mac's
      shell_pkt = PacketFu::TCPPacket.new(:config=>inconfig, :timeout=> 0.1, :flavor=>"Windows")
      shell_pkt.ip_daddr=clientip
      shell_pkt.recalc

      #Mangle Received Packet and Drop on the Wire
      packet.ip_saddr=serverip
      packet.ip_daddr=clientip
      packet.eth_saddr=shell_pkt.eth_saddr
      packet.eth_daddr=clientmac
      packet.recalc
      inj = PacketFu::Inject.new( :iface => "#{inint}", :config =>inconfig )
      inj.a2w(:array => [packet.to_s])
      puts "inpacket processed"
    }
  }
end

#Start Thread from Inside Processing
fromin=Thread.new do
  loop {
    inpcap.stream.each {
      |pkt| packet = PacketFu::Packet.parse(pkt)
   
      if packet.tcp_flags.syn == 1 && packet.tcp_flags.ack == 0
        packet.ip_daddr=serverip
        packet.eth_daddr=servermac
      else
        packet.ip_daddr=bnatip
        packet.eth_daddr=bnatmac
      end
      
      #Build a shell packet that will never hit the wire as a hack to get desired mac's
      shell_pkt = PacketFu::TCPPacket.new(:config=>outconfig, :timeout=> 0.1, :flavor=>"Windows")
      shell_pkt.ip_daddr=serverip
      shell_pkt.recalc

      #Mangle Received Packet and Drop on the Wire
      packet.eth_saddr=shell_pkt.eth_saddr
      packet.recalc
      inj = PacketFu::Inject.new( :iface => "#{outint}", :config =>outconfig )
      inj.a2w(:array => [packet.to_s])
      
      #Double tap that SYN
      if packet.tcp_flags.syn == 1 && packet.tcp_flags.ack == 0
        sleep 0.75
        inj.a2w(:array => [packet.to_s])
      end

      puts "outpacket processed"
    }
  }
end

#Hold Process Open
fromout.join
fromin.join
