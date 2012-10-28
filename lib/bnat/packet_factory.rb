require 'rubygems'
require 'packetfu'

# A factory for generating packet objects on demand

module Bnat 
  class PacketFactory
 
    # @param [String] a string of the interface name
    def initialize(interface)
      @interface = interface
    end

    #Get a Generic TCP Packet
    def get_tcp_packet
      tcp_packet = PacketFu::TCPPacket.new(
        :config=> PacketFu::Utils.whoami?(:iface => "#{@interface}"),
        :timeout=> 0.1,
        :flavor=>"Windows"
      )
      
      return tcp_packet
    end

    # Get a TCP SYN Probe Packet
    # @param opts [Integer] :port the destination port to target
    # @param opts [String] :ip_daddr the destination port to target
    def get_syn_probe(opts = {})
      tcp_syn_probe = get_tcp_packet()
      tcp_syn_probe.tcp_flags.syn=1
      tcp_syn_probe.tcp_win=14600
      tcp_syn_probe.tcp_options="MSS:1460,SACKOK,TS:3853;0,NOP,WS:5"
      tcp_syn_probe.tcp_src = rand(64511)+1024
      tcp_syn_probe.tcp_seq = rand(2**32-10**9)+10**9
      tcp_syn_probe.tcp_dst = opts[:port].to_i if opts[:port]
      tcp_syn_probe.ip_daddr = opts[:ip] if opts[:ip]

      return tcp_syn_probe
    end
    
    # Get a TCP ACK Probe Packet
    def get_ack_probe()
      tcp_ack_probe = get_tcp_packet()
      tcp_ack_probe.tcp_flags.syn = 0
      tcp_ack_probe.tcp_flags.ack = 1

      return tcp_ack_probe
    end
    
    # Get a reflective TCP ACK Probe Packet from a TCP SYN/ACK Packet
    # @param [PacketFu:TCPPacket] a syn/ack packet
    def get_ack_from_syn_ack(syn_ack)
      ack = get_ack_probe()
      ack.ip_saddr = syn_ack.ip_daddr
      ack.ip_daddr = syn_ack.ip_saddr
      ack.eth_saddr = syn_ack.eth_daddr
      ack.eth_daddr = syn_ack.eth_saddr
      ack.tcp_sport = syn_ack.tcp_dport
      ack.tcp_dport = syn_ack.tcp_sport
      ack.tcp_ack = syn_ack.tcp_seq+1
      ack.tcp_seq = syn_ack.tcp_ack
      ack.tcp_win = 183

      return ack
    end

  end
end

