#bnat-simulator - A tool to simulate a BNAT service
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

#Get our local int config
$config = PacketFu::Utils.whoami?() #Learn Auto-magically
#$config = PacketFu::Utils.whoami?(:iface=>"en0") #Manually Specify

#Start capture
cap = PacketFu::Capture.new(
  :iface => $config[:iface], :start => true,
  :filter => "tcp and dst #{$config[:ip_saddr]} and tcp[13] == 2"
)

#Loop through any match to our filter and respond with 192.168.1.1
listen=Thread.new do
loop {cap.stream.each {|pkt| synpkt = PacketFu::Packet.parse(pkt)
    puts "got the syn"
    synackpkt = PacketFu::TCPPacket.new(
      :config=>$config,
      :timeout=> 0.1,
      :flavor=>"Windows"
    )
    #Simulate BNAT SYN/ACK
    synackpkt.ip_saddr="192.168.1.1"
    #Simulate Normal SYN/ACK
    #synackpkt.ip_saddr=synpkt.ip_daddr
    synackpkt.ip_daddr=synpkt.ip_saddr
    synackpkt.eth_saddr=synpkt.eth_daddr
    synackpkt.eth_daddr=synpkt.eth_saddr
    synackpkt.tcp_sport=synpkt.tcp_dport
    synackpkt.tcp_dport=synpkt.tcp_sport
    synackpkt.tcp_flags.syn=1
    synackpkt.tcp_flags.ack=1
    synackpkt.tcp_ack=synpkt.tcp_seq+1
    synackpkt.tcp_seq=rand(64511)+1024
    synackpkt.tcp_win=183
    synackpkt.recalc
    synackpkt.to_w
    puts "sent the syn/ack"
  }
}
end

listen.join