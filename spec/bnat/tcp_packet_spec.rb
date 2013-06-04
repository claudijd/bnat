require 'bnat'

module BNAT
  describe TCPPacket do

    before :each do
      @syn_pkt = BNAT::TCPPacket.new()
      @syn_pkt.ip_saddr = "192.168.1.1"
      @syn_pkt.ip_daddr = "192.168.1.2"
      @syn_pkt.tcp_sport = 12345
      @syn_pkt.tcp_dport = 80
      @syn_pkt.tcp_seq = 10000
      @syn_pkt.tcp_ack = 0

      @syn_pkt_clone = @syn_pkt.dup
    end

    context "when initializing a bnat packet" do
      subject{@syn_pkt}

      its(:class) {should == BNAT::TCPPacket}
      its(:ip_saddr) {should == "192.168.1.1"}
      its(:ip_daddr) {should == "192.168.1.2"}
      its(:tcp_sport) {should == 12345}
      its(:tcp_dport) {should == 80}
      its(:tcp_seq) {should == 10000}
      its(:tcp_ack) {should == 0}
    end

    
    context "when checking the comparison methods against a copy" do
      subject{@syn_pkt}

      it "should be == to the clone" do
        subject.should == @syn_pkt_clone
      end

      it "should be eql? to the clone" do
        subject.eql?(@syn_pkt_clone).should == true
      end

      it "should not be ip_bnat?" do
        subject.ip_bnat?(@syn_pkt_clone).should == false
      end

      it "should not be port_bnat?" do
        subject.port_bnat?(@syn_pkt_clone).should == false
      end

      it "should not be ip_port_bnat?" do
        subject.ip_port_bnat?(@syn_pkt_clone).should == false
      end
    end

    context "when checking the comparison methods against ip_bnat" do
      before :each do
        @syn_ack_pkt = BNAT::TCPPacket.new()
        @syn_ack_pkt.ip_saddr = "192.168.1.3"
        @syn_ack_pkt.ip_daddr = "192.168.1.1"
        @syn_ack_pkt.tcp_sport = 80
        @syn_ack_pkt.tcp_dport = 12345
        @syn_ack_pkt.tcp_seq = 20000
        @syn_ack_pkt.tcp_ack = 10001
      end

      subject{@syn_pkt}

      it "should be ip_bnat?" do
        subject.ip_bnat?(@syn_ack_pkt).should == true
      end

      it "should not be port_bnat?" do
        subject.port_bnat?(@syn_ack_pkt).should == false
      end

      it "should not be ip_port_bnat?" do
        subject.ip_port_bnat?(@syn_ack_pkt).should == false
      end
    end

    context "when checking the comparison methods against port_bnat" do
      before :each do
        @syn_ack_pkt = BNAT::TCPPacket.new()
        @syn_ack_pkt.ip_saddr = "192.168.1.2"
        @syn_ack_pkt.ip_daddr = "192.168.1.1"
        @syn_ack_pkt.tcp_sport = 81
        @syn_ack_pkt.tcp_dport = 12345
        @syn_ack_pkt.tcp_seq = 20000
        @syn_ack_pkt.tcp_ack = 10001
      end

      subject{@syn_pkt}

      it "should not be ip_bnat?" do
        subject.ip_bnat?(@syn_ack_pkt).should == false
      end

      it "should be port_bnat?" do
        subject.port_bnat?(@syn_ack_pkt).should == true
      end

      it "should not be ip_port_bnat?" do
        subject.ip_port_bnat?(@syn_ack_pkt).should == false
      end
    end

    context "when checking the comparison methods against ip_port_bnat" do
      before :each do
        @syn_ack_pkt = BNAT::TCPPacket.new()
        @syn_ack_pkt.ip_saddr = "192.168.1.3"
        @syn_ack_pkt.ip_daddr = "192.168.1.1"
        @syn_ack_pkt.tcp_sport = 81
        @syn_ack_pkt.tcp_dport = 12345
        @syn_ack_pkt.tcp_seq = 20000
        @syn_ack_pkt.tcp_ack = 10001
      end

      subject{@syn_pkt}

      it "should not be ip_bnat?" do
        subject.ip_bnat?(@syn_ack_pkt).should == false
      end

      it "should not be port_bnat?" do
        subject.port_bnat?(@syn_ack_pkt).should == false
      end

      it "should be ip_port_bnat?" do
        subject.ip_port_bnat?(@syn_ack_pkt).should == true
      end
    end

  end
end
