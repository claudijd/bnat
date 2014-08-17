require 'json'

module BNAT
  class Result
    include BNAT::Common

    def initialize(request_packet, response_packet)
      @request_packet = request_packet
      @response_packet = response_packet
    end

    def to_hash
      {
        :request_packet => packet_to_hash(@request_packet),
        :response_packet => packet_to_hash(@response_packet)
      }
    end

    def to_json
      JSON.generate(self.to_hash)
    end

    def to_xml
      builder = Nokogiri::XML::Builder.new do |xml|
                  xml.result {
                    xml.request_packet {
                      xml << packet_to_xml(@request_packet) 
                    }
                    xml.response_packet {
                      xml << packet_to_xml(@response_packet) 
                    }
                  }
                end

      builder.doc.root.to_xml
    end

    def to_s
      "BNAT Service at #{@request_packet.ip_daddr}:#{@request_packet.tcp_dport}\n" + 
      "\tRequest: #{@request_packet.ip_daddr}:#{@request_packet.tcp_dport} (Seq: #{@request_packet.tcp_seq})\n" + 
      "\tResponse: #{@response_packet.ip_saddr}:#{@response_packet.tcp_sport} (Ack: #{@response_packet.tcp_ack})"
    end

  end
end