require 'packetfu'
require 'nokogiri'

module BNAT
  module Common

    # Helper to turn a packet into a simplified hash
    # @param [PacketFu::TCPPacket] packet
    # @return [String]
    def packet_to_hash(packet)
      {
        :eth_saddr => packet.eth_saddr,
        :eth_daddr => packet.eth_daddr,
        :ip_saddr  => packet.ip_saddr,
        :ip_daddr  => packet.ip_daddr,
        :tcp_sport => packet.tcp_sport,
        :tcp_dport => packet.tcp_dport,
        :tcp_seq   => packet.tcp_seq,
        :tcp_ack   => packet.tcp_ack,
        :tcp_flags => packet.tcp_flags.to_h
      }
    end

    # Helper to turn a packet into a simplified hash
    # @param [PacketFu::TCPPacket] packet
    # @return [String]
    def packet_to_xml(packet)
      builder = Nokogiri::XML::Builder.new do |xml|
                  xml.packet {
                    xml.eth_saddr = packet.eth_saddr
                    xml.eth_daddr = packet.eth_daddr
                    xml.ip_saddr  = packet.ip_saddr
                    xml.ip_daddr  = packet.ip_daddr
                    xml.tcp_sport = packet.tcp_sport
                    xml.tcp_dport = packet.tcp_dport
                    xml.tcp_seq   = packet.tcp_seq
                    xml.tcp_ack   = packet.tcp_ack
                    xml.tcp_flags {
                      xml.urg = packet.tcp_flags.to_h[:urg]
                      xml.ack = packet.tcp_flags.to_h[:ack]
                      xml.psh = packet.tcp_flags.to_h[:psh]
                      xml.rst = packet.tcp_flags.to_h[:rst]
                      xml.syn = packet.tcp_flags.to_h[:syn]
                      xml.fin = packet.tcp_flags.to_h[:fin]
                    }
                  }
                end

      builder.doc.root.to_xml(:indent => 2)
    end

    # Helper for generating a TCPPacket
    # @param [PacketFu::Config] config (optional)
    # @return [PacketFu::TCPPacket] packet
    def get_tcp_packet(config = nil)
      PacketFu::TCPPacket.new(
        :config=> config,
        :timeout=> 0.1,
        :flavor=> "Windows"
      )
    end

    # # A helper for generating TCP Packets
    # # @param [PacketFu::Config] config (optional)
    # # @return [PacketFu::TCPPacket]
    # def get_tcp_packet(config = nil)
    #   BNAT::TCPPacket.new(
    #     :config => config,
    #     :timeout => 0.1,
    #     :flavor => "Windows"
    #   )
    # end

    # # A helper for generating a reflective packets
    # # @param [PacketFu::TCPPacket] first_pkt
    # # @param [PacketFu::Config] config (optional)
    # # @return [PacketFu::TCPPacket] second_pkt
    # def get_reflective_packet(first_pkt, config = nil)
    #   second_pkt = get_tcp_packet(config)

    #   second_pkt.ip_saddr = first_pkt.ip_daddr
    #   second_pkt.ip_daddr = first_pkt.ip_saddr
    #   second_pkt.eth_saddr = first_pkt.eth_daddr
    #   second_pkt.eth_daddr = first_pkt.eth_saddr
    #   second_pkt.tcp_sport = first_pkt.tcp_dport
    #   second_pkt.tcp_dport = first_pkt.tcp_sport

    #   return second_pkt
    # end

    # # A helper for generating a reflective SYN/ACK
    # # @param [PacketFu::TCPPacket] syn_pkt
    # # @param [PacketFu::Config] config (optional) 
    # # @return [PacketFu::TCPPacket] syn_ack_pkt
    # def get_reflective_syn_ack(syn_pkt, config = nil)
    #   syn_ack_pkt = get_reflective_packet(syn_pkt, config)
    #   syn_ack_pkt.tcp_flags.syn = 1
    #   syn_ack_pkt.tcp_flags.ack = 1
    #   syn_ack_pkt.tcp_ack = syn_pkt.tcp_seq + 1
    #   syn_ack_pkt.tcp_seq = rand(64511) + 1024
    #   syn_ack_pkt.tcp_win = 183

    #   return syn_ack_pkt
    # end

    # # A helper for generating a reflective PSH/ACK
    # # @param [PacketFu::TCPPacket] ack_pkt
    # # @param [PacketFu::Config] config (optional) 
    # # @return [PacketFu::TCPPacket] psh_ack_pkt
    # def get_reflective_psh_ack(ack_pkt, config = nil)
    #   psh_ack_pkt = get_reflective_packet(ack_pkt, config)
    #   psh_ack_pkt.tcp_flags.syn = 0
    #   psh_ack_pkt.tcp_flags.psh = 1
    #   psh_ack_pkt.tcp_flags.ack = 1
    #   psh_ack_pkt.tcp_ack = ack_pkt.tcp_seq
    #   psh_ack_pkt.tcp_seq = ack_pkt.tcp_ack

    #   return psh_ack_pkt
    # end

    # # A helper for generating a reflective PSH/ACK
    # # @param [PacketFu::TCPPacket] syn_ack_pkt
    # # @param [PacketFu::Config] config (optional) 
    # # @return [PacketFu::TCPPacket] ack_pkt
    # def get_reflective_ack(syn_ack_pkt, config = nil)
    #   ack_pkt = get_reflective_packet(syn_ack_pkt, config)
    #   ack_pkt.tcp_flags.syn = 0
    #   ack_pkt.tcp_flags.psh = 0
    #   ack_pkt.tcp_flags.ack = 1
    #   ack_pkt.tcp_ack = syn_ack_pkt.tcp_seq + 1
    #   ack_pkt.tcp_seq = syn_ack_pkt.tcp_ack

    #   return ack_pkt
    # end  

    # # A helper for generating packet captures
    # # @param [String] int - The interface name
    # # @param [String] filter - The BPF filter for the capture 
    # # @return [PacketFu::Capture]
    # def get_capture(int, filter)
    #   PacketFu::Capture.new(
    #     :iface => int,
    #     :start => true,
    #     :filter => filter
    #   )
    # end

    # # A helper for generating a reflective BPF filter string
    # # @param [PacketFu::TCPPacket] pkt
    # # @param [String] filter - The BPF filter that's reflective to this packet
    # def get_reflective_bpf(pkt)
    #   "src #{pkt.ip_daddr} " +
    #   "and dst #{pkt.ip_saddr} " +
    #   "and src port #{pkt.tcp_dport} " +
    #   "and dst port #{pkt.tcp_sport}"
    # end

  end
end

