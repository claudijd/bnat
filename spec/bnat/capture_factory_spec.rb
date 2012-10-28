require 'spec_helper'
require 'rubygems'
require 'bnat'
require 'packetfu'

module Bnat
  describe CaptureFactory do

    before :each do
      @cf = Bnat::CaptureFactory.new('eth0')
    end

    context "when initializing a bnat capture factory" do
      subject{@cf}
      its(:class) {should == Bnat::CaptureFactory}
    end
    
    context "when getting a capture" do
      subject{@cf}
      
      it "should be the right capture class" do
        @cf.get_capture.class.should == PacketFu::Capture
      end
    end

  end
end