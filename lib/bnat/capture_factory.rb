require 'packetfu'
require 'set'

# A factory for generating capturing objects on demand

module Bnat 
  class CaptureFactory

    attr_reader :configs, :interfaces
 
    # @param [Array>String] an array of interface names to handle captures for
    def initialize(raw_interfaces)
      @raw_interfaces = raw_interfaces
      @interfaces = Set.new
      @configs = Set.new

      generate_interfaces()
      generate_configs()
    end

    # Generate interfaces for all raw_interfaces supplied in construction    
    def generate_interfaces
      @raw_interfaces.each {|i| @interfaces << PacketFu::Utils.ifconfig(i)}
    end

    # Generate configs for all interfaces on this class
    def generate_configs
      @interfaces.each {|i| @configs << generate_config(i)}
    end

    # Generate a config from a given interface hash
    # @param [Hash] a hash of interface attributes (Example: "eth0")
    def generate_config(interface)
      PacketFu::Config.new(interface)
    end

    # Obtain a PacketFu::Capture Object based on a BPF and/or Interface
    # @param [String] the bpf/filter to use for the capture (optional)
    # @param [String] the interface the capture should be for (optional)
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

    # Obtain a PacketFu::Config Object based on an Interface
    # @param [String] the interface the capture should be for (optional)
    def get_config(raw_interface = @raw_interfaces.first)
      @configs.select {|c| c.iface == raw_interface}.first
    end

  end
end

