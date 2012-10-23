require 'spec_helper'
require 'bnat'
require 'packetfu'

module Bnat
  describe Packet do

    before :each do
      @syn_pkt = PacketFu::TCPPacket.new()
      @syn_pkt.ip_saddr = "192.168.1.1"
      @syn_pkt.ip_daddr = "192.168.1.2"
      @syn_pkt.tcp_sport = 12345
      @syn_pkt.tcp_dport = 80
      @syn_pkt.tcp_seq = 10000
      @syn_pkt.tcp_ack = 0

      @syn_packet = Bnat::Packet.new(@syn_pkt)
    end

    context "when initializing a bnat packet" do
      subject{@syn_packet}

      its(:class) {should == Bnat::Packet}
      its(:src_ip) {should == "192.168.1.1"}
      its(:dst_ip) {should == "192.168.1.2"}
      its(:src_port) {should == 12345}
      its(:dst_port) {should == 80}
      its(:seq) {should == 10000}
      its(:ack) {should == 0}

    end

    context "when comparing bnat packet equality" do

      before :each do
        @syn_packet2 = @syn_packet.dup
        @syn_packet3 = @syn_packet.dup
        @syn_packet3.dst_ip = "192.168.1.3"
      end

      subject{@syn_packet}

      it "should be eql? to itself" do
        @syn_packet.eql?(@syn_packet).should == true
      end

      it "should be eql? to tcp packet 2" do
        @syn_packet.eql?(@syn_packet2).should == true
      end

      it "should not be eql? to tcp packet 2" do
        @syn_packet.eql?(@syn_packet3).should_not == true
      end

    end

    context "when checking for ip-based bnat" do

      before :each do
        @syn_ack_pkt = PacketFu::TCPPacket.new()
        @syn_ack_pkt.ip_saddr = "192.168.1.2"
        @syn_ack_pkt.ip_daddr = "192.168.1.1"
        @syn_ack_pkt.tcp_sport = 80
        @syn_ack_pkt.tcp_dport = 12345
        @syn_ack_pkt.tcp_seq = 30000
        @syn_ack_pkt.tcp_ack = 10001
        @syn_ack_packet = Bnat::Packet.new(@syn_ack_pkt)

        @syn_ack_bnat_pkt = PacketFu::TCPPacket.new()
        @syn_ack_bnat_pkt.ip_saddr = "192.168.1.3"
        @syn_ack_bnat_pkt.ip_daddr = "192.168.1.1"
        @syn_ack_bnat_pkt.tcp_sport = 80
        @syn_ack_bnat_pkt.tcp_dport = 12345
        @syn_ack_bnat_pkt.tcp_seq = 30000
        @syn_ack_bnat_pkt.tcp_ack = 10001
        @syn_ack_bnat_packet = Bnat::Packet.new(@syn_ack_bnat_pkt)
      end

      subject{@syn_packet}

      it "should not detect ip-based bnat" do
        @syn_packet.ip_bnat?(@syn_ack_packet).should == false
      end

      it "should detect ip-based bnat" do
        @syn_packet.ip_bnat?(@syn_ack_bnat_packet).should == true
      end

    end

    context "when checking for port-based bnat" do

      before :each do
        @syn_ack_pkt = PacketFu::TCPPacket.new()
        @syn_ack_pkt.ip_saddr = "192.168.1.2"
        @syn_ack_pkt.ip_daddr = "192.168.1.1"
        @syn_ack_pkt.tcp_sport = 80
        @syn_ack_pkt.tcp_dport = 12345
        @syn_ack_pkt.tcp_seq = 30000
        @syn_ack_pkt.tcp_ack = 10001
        @syn_ack_packet = Bnat::Packet.new(@syn_ack_pkt)

        @syn_ack_bnat_pkt = PacketFu::TCPPacket.new()
        @syn_ack_bnat_pkt.ip_saddr = "192.168.1.2"
        @syn_ack_bnat_pkt.ip_daddr = "192.168.1.1"
        @syn_ack_bnat_pkt.tcp_sport = 81
        @syn_ack_bnat_pkt.tcp_dport = 12345
        @syn_ack_bnat_pkt.tcp_seq = 30000
        @syn_ack_bnat_pkt.tcp_ack = 10001
        @syn_ack_bnat_packet = Bnat::Packet.new(@syn_ack_bnat_pkt)
      end

      subject{@syn_packet}

      it "should not detect port-based bnat" do
        @syn_packet.port_bnat?(@syn_ack_packet).should == false
      end

      it "should detect port-based bnat" do
        @syn_packet.port_bnat?(@syn_ack_bnat_packet).should == true
      end

    end

    context "when checking for ip-port-based bnat" do

      before :each do
        @syn_ack_pkt = PacketFu::TCPPacket.new()
        @syn_ack_pkt.ip_saddr = "192.168.1.2"
        @syn_ack_pkt.ip_daddr = "192.168.1.1"
        @syn_ack_pkt.tcp_sport = 80
        @syn_ack_pkt.tcp_dport = 12345
        @syn_ack_pkt.tcp_seq = 30000
        @syn_ack_pkt.tcp_ack = 10001
        @syn_ack_packet = Bnat::Packet.new(@syn_ack_pkt)

        @syn_ack_bnat_pkt = PacketFu::TCPPacket.new()
        @syn_ack_bnat_pkt.ip_saddr = "192.168.1.3"
        @syn_ack_bnat_pkt.ip_daddr = "192.168.1.1"
        @syn_ack_bnat_pkt.tcp_sport = 81
        @syn_ack_bnat_pkt.tcp_dport = 12345
        @syn_ack_bnat_pkt.tcp_seq = 30000
        @syn_ack_bnat_pkt.tcp_ack = 10001
        @syn_ack_bnat_packet = Bnat::Packet.new(@syn_ack_bnat_pkt)
      end

      subject{@syn_packet}

      it "should not detect ip-port-based bnat" do
        @syn_packet.ip_port_bnat?(@syn_ack_packet).should == false
      end

      it "should detect ip-port-based bnat" do
        @syn_packet.ip_port_bnat?(@syn_ack_bnat_packet).should == true
      end

    end

  end
end
