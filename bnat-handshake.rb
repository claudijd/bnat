#bnat-handshake - A tool to PoC that BNAT tcp handshakes for advanced scenerios can be completed with "reflective acking" a SYN/ACK
#Jonathan Claudius
#Copyright (C) 2011 Trustwave
#
#This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#
#This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.

require 'packetfu'

$target = ARGV[0]
$port = ARGV[1]
$gatewaymac= ARGV[2]

#usage: ruby bnat-handshake.rb <targetip> <port>
#example: ruby bnat-handshake.rb 74.125.225.84 80

#Get our local int config
$config = PacketFu::Utils.whoami?()

#Build out a Raw TCP Packet
synpkt = PacketFu::TCPPacket.new(:config=>$config, :timeout=> 0.1, :flavor=>"Windows")
synpkt.ip_saddr=$config[:ip_saddr]
synpkt.ip_daddr="#{$target}"
synpkt.tcp_sport=rand(64511)+1024
synpkt.tcp_dport=$port.to_i
synpkt.tcp_win=14600
synpkt.tcp_options="MSS:1460,SACKOK,TS:3853;0,NOP,WS:5"
synpkt.eth_daddr=$gatewaymac
synpkt.tcp_flags.syn=1
synpkt.recalc

#Start capture
cap = PacketFu::Capture.new(:iface => $config[:iface], :start => true, :filter => "tcp and dst #{$config[:ip_saddr]} and tcp[13] == 18")

#push syn to wire
synpkt.to_w
puts "sent the syn"

listen=Thread.new do
loop {cap.stream.each {|pkt| packet = PacketFu::Packet.parse(pkt)
      puts "got the syn/ack"
      ackpkt = PacketFu::TCPPacket.new(:config=>$config, :timeout=> 0.1, :flavor=>"Windows")
      ackpkt.ip_saddr=packet.ip_daddr
      ackpkt.ip_daddr=packet.ip_saddr
      ackpkt.eth_saddr=packet.eth_daddr
      ackpkt.eth_daddr=packet.eth_saddr
      ackpkt.tcp_sport=packet.tcp_dport
      ackpkt.tcp_dport=packet.tcp_sport
      ackpkt.tcp_flags.syn=0
      ackpkt.tcp_flags.ack=1
      ackpkt.tcp_ack=packet.tcp_seq+1
      ackpkt.tcp_seq=packet.tcp_ack
      ackpkt.tcp_win=183
      ackpkt.recalc
      ackpkt.to_w
      puts "sent the ack"
   }
}
end

listen.join