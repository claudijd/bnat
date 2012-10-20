require 'packetfu'
require 'set'

module Bnat
  class CaptureFactory

    attr_reader :configs, :interfaces

    # A factory for generating capturing objects on demand
      
    # @param [Array>String] an array of interface names to handle captures for
    def initialize(raw_interfaces)
      @raw_interfaces = raw_interfaces
      @interfaces = Set.new
      @configs = Set.new

      generate_interfaces()
      generate_configs()
    end

    def generate_interfaces
      @raw_interfaces.each do |i|
        @interfaces << PacketFu::Utils.ifconfig(i)
      end
    end

    def generate_configs
      @interfaces.each do |i|
        @configs << generate_config(i)
      end
    end

    # @param [Hash] a hash of interface attributes
    def generate_config(interface)
      PacketFu::Config.new(interface)
    end

    # @param [String] the bpf/filter to use for the capture (optional)
    # @param [String] the interface the capture should be for 
    # @return [PacketFu::Capture] the capture object    
    def get_capture(bpf = "tcp", raw_interface = @raw_interfaces.first)
      config = get_config(raw_interface)
      
      ret = PacketFu::Capture.new(
        :config => config,
        :start => true,
        :bpf => bpf
      )

      return ret
    end

    # @param [String] the interface the capture should be for
    def get_config(raw_interface = @raw_interfaces.first)
      @configs.select {|c| c.iface == raw_interface}.first
    end

  end
end

