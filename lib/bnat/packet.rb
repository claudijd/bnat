require 'rubygems'
require 'packetfu'

module Bnat
  class Packet
    attr_accessor :src_ip, :dst_ip, :src_port, :dst_port, :seq, :ack

    # @param [PacketFu::Packet] The source packet of comparison
    def initialize(packet)
      @src_ip = packet.ip_saddr
      @dst_ip = packet.ip_daddr
      @src_port = packet.tcp_sport
      @dst_port = packet.tcp_dport
      @seq = packet.tcp_seq
      @ack = packet.tcp_ack
    end

    # Check to see if values are equal
    # @param [Bnat::Packet] an arbitrary Bnat::Packet object
    # @return [true, false] response is either true or false
    def ==(other)
      self.src_ip == other.src_ip &&
        self.dst_ip == other.dst_ip &&
        self.src_port == other.src_port &&
        self.dst_port == other.dst_port &&
        self.seq == other.seq &&
        self.ack == other.ack
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
      self.src_ip == other.dst_ip &&
        self.dst_ip != other.src_ip &&
        self.src_port == other.dst_port &&
        self.dst_port == other.src_port &&
        self.seq + 1 == other.ack
    end

    # Check to see if packets are an Port-based bnat pair
    # @param [Bnat::Packet] an arbitrary Bnat::Packet object
    # @return [true, false] response is either true or false
    def port_bnat?(other)
      self.src_ip == other.dst_ip &&
        self.dst_ip == other.src_ip &&
        self.src_port == other.dst_port &&
        self.dst_port != other.src_port &&
        self.seq + 1 == other.ack
    end

    # Check to see if packets are an IP & Port-based bnat pair
    # @param [Bnat::Packet] an arbitrary Bnat::Packet object
    # @return [true, false] response is either true or false
    def ip_port_bnat?(other)
      self.src_ip == other.dst_ip &&
        self.dst_ip != other.src_ip &&
        self.src_port == other.dst_port &&
        self.dst_port != other.src_port &&
        self.seq + 1 == other.ack
    end

  end
end
