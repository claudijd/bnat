require 'packetfu'

module BNAT
  class TCPPacket < PacketFu::TCPPacket

    # Check to see if values are equal
    # @param [Bnat::Packet] an arbitrary Bnat::Packet object
    # @return [true, false] response is either true or false
    def ==(other)
      self.ip_saddr == other.ip_daddr      
      self.ip_daddr == other.ip_saddr      
      self.tcp_sport == other.tcp_dport      
      self.tcp_dport == other.tcp_sport      
      self.tcp_seq == other.tcp_seq &&
      self.tcp_ack == other.tcp_ack
    end

    # Check to see if values are equal and of the same type
    # @param [Bnat::Packet] an arbitrary Bnat::Packet object
    # @return [true, false] response is either true or false
    def eql?(other)
      self.class == other.class &&
      self == other
    end

    # Check to see if packets are an IP-based bnat pair
    # @param [Bnat::Packet] an arbitrary Bnat::Packet object
    # @return [true, false] response is either true or false
    def ip_bnat?(other)
      src_ip_match?(other) == false &&
      dst_ip_match?(other) == true &&
      port_match?(other) == true &&
      ack_match?(other) == true
    end

    # Check to see if packets are an Port-based bnat pair
    # @param [Bnat::Packet] an arbitrary Bnat::Packet object
    # @return [true, false] response is either true or false
    def port_bnat?(other)
      ip_match?(other) == true &&
      src_port_match?(other) == false &&
      dst_port_match?(other) == true &&
      ack_match?(other) == true
    end

    # Check to see if packets are an IP & Port-based bnat pair
    # @param [Bnat::Packet] an arbitrary Bnat::Packet object
    # @return [true, false] response is either true or false
    def ip_port_bnat?(other)
      src_ip_match?(other) == false &&
      dst_ip_match?(other) == true &&
      src_port_match?(other) == false &&
      dst_port_match?(other) == true &&
      ack_match?(other) == true
    end

    # Determine if the ips of the packets 
    # reflectively match
    # @param [Bnat::Packet] other
    # @return [true, false]
    def ip_match?(other)
      src_ip_match?(other) &&
      dst_ip_match?(other)
    end

    # Determine if the ports of the packets 
    # reflectively match
    # @param [Bnat::Packet] other
    # @return [true, false]
    def port_match?(other)
      src_port_match?(other) &&
      dst_port_match?(other)
    end

    # Determine if the src ip of the packet 
    # matches the dst ip we sent to
    # @param [Bnat::Packet] other
    # @return [true, false]
    def src_ip_match?(other)
      self.ip_daddr == other.ip_saddr
    end

    # Determine if the dst ip of the packet 
    # matches the src ip we sent from
    # @param [Bnat::Packet] other
    # @return [true, false]
    def dst_ip_match?(other)
      self.ip_saddr == other.ip_daddr      
    end

    # Determine if the src port of the packet 
    # matches the dst port we sent to
    # @param [Bnat::Packet] other
    # @return [true, false]
    def src_port_match?(other)
      self.tcp_dport == other.tcp_sport
    end

    # Determine if the dst port of the packet 
    # matches the src port we sent from
    # @param [Bnat::Packet] other
    # @return [true, false]
    def dst_port_match?(other)
      self.tcp_sport == other.tcp_dport      
    end
    
    # Determine if the ack of the packet 
    # matches the seq we sent from
    # @param [Bnat::Packet] other
    # @return [true, false]
    def ack_match?(other)
      self.tcp_seq + 1 == other.tcp_ack
    end

  end
end
