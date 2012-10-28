require 'spec_helper'
require 'rubygems'
require 'bnat'
require 'packetfu'

module Bnat
  describe PacketFactory do

    before :each do
      @pf = Bnat::PacketFactory.new('eth0')
    end

    context "when initializing a bnat packet factory" do
      subject{@pf}
      its(:class) {should == Bnat::PacketFactory}
    end

    context "when getting a generic tcp packet" do
      subject{@pf}
      
      it "should be the right class" do
        @pf.get_tcp_packet.class.should == PacketFu::TCPPacket
      end
    end
    
    context "when getting a syn tcp packet" do
      subject{@pf}
      
      it "should be the right class" do
        @pf.get_syn_probe.class.should == PacketFu::TCPPacket
      end
      
      it "should be a syn packet" do
        @pf.get_syn_probe.tcp_flags.syn.should == 1
      end
    end

    context "when getting 1000 syn tcp packets" do
      before :each do
        @packets = (1..1000).collect {@pf.get_syn_probe}
      end
      
      it "should generate one thousand packets" do
        @packets.size.should == 1000
      end
      
      it "should generate uniq sequence number and source port pairs" do
        @packets.collect {|p| [p.tcp_seq, p.tcp_seq]}.uniq.size.should == 1000
      end

    end

  end
end