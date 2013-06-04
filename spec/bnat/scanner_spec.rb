#require 'spec_helper'
#require 'bnat'
#require 'packetfu'
#
#module Bnat
#  describe Scanner do
#
#    before :each do
#      @opts = {
#        :iface => "eth0",
#        :ports => [80,443],
#        :targets => [
#          "192.168.1.1",
#          "192.168.1.2"
#        ]
#      }
#      @scanner = Bnat::Scanner.new(@opts)
#    end
#
#    context "when initializing a scanner object" do
#      subject{@scanner}
#
#      its(:class) {should == Bnat::Scanner}
#      its(:iface) {should == "eth0"}
#      its(:ports) {should == [80,443]}
#      its(:targets) {should == ["192.168.1.1", "192.168.1.2"]}
#      
#      it "should have the right pf class" do
#        @scanner.pf.class.should == Bnat::PacketFactory
#      end
#      
#    end
#    
#  end
#end
