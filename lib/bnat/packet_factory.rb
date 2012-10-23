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
        :iface=> @interface,
        :timeout=> 0.1,
        :flavor=>"Windows"
      )
      
      return tcp_packet
    end

    # Get a TCP SYN Probe Packet  
    def get_syn_probe
      tcp_syn_probe = get_tcp_packet
      tcp_syn_probe.tcp_flags.syn=1
      tcp_syn_probe.tcp_win=14600
      tcp_syn_probe.tcp_options="MSS:1460,SACKOK,TS:3853;0,NOP,WS:5"
      tcp_syn_probe.tcp_src = rand(64511)+1024
      tcp_syn_probe.tcp_seq = rand(64511)+1024

      return tcp_syn_probe
    end

  end
end

