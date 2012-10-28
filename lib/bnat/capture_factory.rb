require 'rubygems'
require 'packetfu'
require 'set'

# A factory for generating capturing objects on demand

module Bnat 
  class CaptureFactory

    attr_reader :configs, :interface
 
    # @param [String] a string of the interface name
    def initialize(interface)
      @interface = interface
    end

    # Obtain a PacketFu::Capture Object based on a BPF and/or Interface
    # @param [String] the bpf/filter to use for the capture (optional)
    # @return [PacketFu::Capture] the capture object    
    def get_capture(bpf = "tcp")
      ret = PacketFu::Capture.new(
        :iface => @interface,
        :start => true,
        :filter => bpf
      )

      return ret
    end

  end
end

