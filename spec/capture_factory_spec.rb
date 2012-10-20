require 'bnat'
require 'packetfu'

module Bnat
  describe CaptureFactory do

    before :each do
      @raw_interfaces = ['en0']
      @cf = Bnat::CaptureFactory.new(@raw_interfaces)
    end

    context "when initializing a bnat capture factory" do
      subject{@cf}
      its(:class) {should == Bnat::CaptureFactory}
    end

    context "when requesting a config for an instance using default interface" do
      before :each do
        @pcap = @cf.get_config()
      end

      subject{@pcap}
      its(:class) {should == PacketFu::Config}
    end

    context "when requesting a config for an instance using explicit interface" do
      before :each do
        @pcap = @cf.get_config(@raw_interfaces.first)
      end

      subject{@pcap}
      its(:class) {should == PacketFu::Config}
    end

    context "when requesting a capture instance using default interface" do
      before :each do
        @pcap = @cf.get_capture('tcp')
      end

      subject{@pcap}
      its(:class) {should == PacketFu::Capture}
    end

    context "when requesting a capture instance using explicit interface" do
      before :each do
        @pcap = @cf.get_capture('tcp', @raw_interfaces.first)
      end

      subject{@pcap}
      its(:class) {should == PacketFu::Capture}
    end

  end
end
