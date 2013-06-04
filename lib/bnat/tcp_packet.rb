require 'packetfu'

module BNAT
  class TCPPacket < PacketFu::TCPPacket

    # Check to see if values are equal
    # @param [Bnat::Packet] an arbitrary Bnat::Packet object
    # @return [true, false] response is either true or false
    def ==(other)
      self.ip_saddr == other.ip_saddr &&
      self.ip_daddr == other.ip_daddr &&
      self.tcp_sport == other.tcp_sport &&
      self.tcp_dport == other.tcp_dport &&
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
      self.ip_saddr == other.ip_daddr &&
      self.ip_daddr != other.ip_saddr &&
      self.tcp_sport == other.tcp_dport &&
      self.tcp_dport == other.tcp_sport &&
      self.tcp_seq + 1 == other.tcp_ack
    end

    # Check to see if packets are an Port-based bnat pair
    # @param [Bnat::Packet] an arbitrary Bnat::Packet object
    # @return [true, false] response is either true or false
    def port_bnat?(other)
      self.ip_saddr == other.ip_daddr &&
      self.ip_daddr == other.ip_saddr &&
      self.tcp_sport == other.tcp_dport &&
      self.tcp_dport != other.tcp_sport &&
      self.tcp_seq + 1 == other.tcp_ack
    end

    # Check to see if packets are an IP & Port-based bnat pair
    # @param [Bnat::Packet] an arbitrary Bnat::Packet object
    # @return [true, false] response is either true or false
    def ip_port_bnat?(other)
      self.ip_saddr == other.ip_daddr &&
      self.ip_daddr != other.ip_saddr &&
      self.tcp_sport == other.tcp_dport &&
      self.tcp_dport != other.tcp_sport &&
      self.tcp_seq + 1 == other.tcp_ack
    end

  end
end
