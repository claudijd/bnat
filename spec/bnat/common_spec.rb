require 'bnat'

module BNAT
  describe Common do
    before :each do
      @helper = class Helper
                  include BNAT::Common
                end.new
    end

    it "should generate a TCP packet" do
      @helper.get_tcp_packet().should be_kind_of(PacketFu::TCPPacket)
    end

    context "when generating generic reflective packets" do
      before :each do
        @first_pkt = @helper.get_tcp_packet()
        @first_pkt.ip_saddr = "192.168.1.1"
        @first_pkt.ip_daddr = "192.168.1.2"
        @first_pkt.eth_saddr = "aa:aa:aa:aa:aa:aa"
        @first_pkt.eth_daddr = "bb:bb:bb:bb:bb:bb"
        @first_pkt.tcp_sport = 12345
        @first_pkt.tcp_dport = 80

        @second = @helper.get_reflective_packet(@first_pkt)
      end

      subject{@second}

      its(:class) {should == PacketFu::TCPPacket}
      its(:ip_saddr) {should == "192.168.1.2"}
      its(:ip_daddr) {should == "192.168.1.1"}
      its(:eth_saddr) {should == "bb:bb:bb:bb:bb:bb"}
      its(:eth_daddr) {should == "aa:aa:aa:aa:aa:aa"}
      its(:tcp_sport) {should == 80}
      its(:tcp_dport) {should == 12345}
    end

    context "when generating reflective syn ack packets" do
      before :each do
        @syn_pkt = @helper.get_tcp_packet()
        @syn_pkt.ip_saddr = "192.168.1.1"
        @syn_pkt.ip_daddr = "192.168.1.2"
        @syn_pkt.eth_saddr = "aa:aa:aa:aa:aa:aa"
        @syn_pkt.eth_daddr = "bb:bb:bb:bb:bb:bb"
        @syn_pkt.tcp_sport = 12345
        @syn_pkt.tcp_dport = 80
        @syn_pkt.tcp_flags.syn = 1
        @syn_pkt.tcp_flags.ack = 0

        @syn_ack_pkt = @helper.get_reflective_syn_ack(@syn_pkt)
      end

      subject{@syn_ack_pkt}

      its(:class) {should == PacketFu::TCPPacket}
      its(:ip_saddr) {should == "192.168.1.2"}
      its(:ip_daddr) {should == "192.168.1.1"}
      its(:eth_saddr) {should == "bb:bb:bb:bb:bb:bb"}
      its(:eth_daddr) {should == "aa:aa:aa:aa:aa:aa"}
      its(:tcp_sport) {should == 80}
      its(:tcp_dport) {should == 12345}
      its(:tcp_win) {should == 183}
      its(:tcp_ack) {should == @syn_pkt.tcp_seq + 1}

      it "should have the right tcp_flags" do
        subject.tcp_flags.syn.should == 1
        subject.tcp_flags.ack.should == 1
      end
    end

    context "when generating reflective psh ack packets" do
      before :each do
        @ack_pkt = @helper.get_tcp_packet()
        @ack_pkt.ip_saddr = "192.168.1.1"
        @ack_pkt.ip_daddr = "192.168.1.2"
        @ack_pkt.eth_saddr = "aa:aa:aa:aa:aa:aa"
        @ack_pkt.eth_daddr = "bb:bb:bb:bb:bb:bb"
        @ack_pkt.tcp_sport = 12345
        @ack_pkt.tcp_dport = 80
        @ack_pkt.tcp_flags.syn = 1
        @ack_pkt.tcp_flags.ack = 1
        @ack_pkt.tcp_seq = 11111
        @ack_pkt.tcp_ack = 22222

        @psh_ack_pkt = @helper.get_reflective_psh_ack(@ack_pkt)
      end

      subject{@psh_ack_pkt}

      its(:class) {should == PacketFu::TCPPacket}
      its(:ip_saddr) {should == "192.168.1.2"}
      its(:ip_daddr) {should == "192.168.1.1"}
      its(:eth_saddr) {should == "bb:bb:bb:bb:bb:bb"}
      its(:eth_daddr) {should == "aa:aa:aa:aa:aa:aa"}
      its(:tcp_sport) {should == 80}
      its(:tcp_dport) {should == 12345}
      its(:tcp_seq) {should == @ack_pkt.tcp_ack}
      its(:tcp_ack) {should == @ack_pkt.tcp_seq}

      it "should have the right tcp_flags" do
        subject.tcp_flags.syn.should == 0
        subject.tcp_flags.psh.should == 1
        subject.tcp_flags.ack.should == 1
      end
    end

    context "when generating reflective ack packets" do
      before :each do
        @syn_ack_pkt = @helper.get_tcp_packet()
        @syn_ack_pkt.ip_saddr = "192.168.1.1"
        @syn_ack_pkt.ip_daddr = "192.168.1.2"
        @syn_ack_pkt.eth_saddr = "aa:aa:aa:aa:aa:aa"
        @syn_ack_pkt.eth_daddr = "bb:bb:bb:bb:bb:bb"
        @syn_ack_pkt.tcp_sport = 12345
        @syn_ack_pkt.tcp_dport = 80
        @syn_ack_pkt.tcp_flags.syn = 1
        @syn_ack_pkt.tcp_flags.ack = 1
        @syn_ack_pkt.tcp_flags.psh = 0 
        @syn_ack_pkt.tcp_seq = 11111
        @syn_ack_pkt.tcp_ack = 22222

        @ack_pkt = @helper.get_reflective_ack(@syn_ack_pkt)
      end

      subject{@ack_pkt}

      its(:class) {should == PacketFu::TCPPacket}
      its(:ip_saddr) {should == "192.168.1.2"}
      its(:ip_daddr) {should == "192.168.1.1"}
      its(:eth_saddr) {should == "bb:bb:bb:bb:bb:bb"}
      its(:eth_daddr) {should == "aa:aa:aa:aa:aa:aa"}
      its(:tcp_sport) {should == 80}
      its(:tcp_dport) {should == 12345}
      its(:tcp_seq) {should == @syn_ack_pkt.tcp_ack}
      its(:tcp_ack) {should == @syn_ack_pkt.tcp_seq + 1}

      it "should have the right tcp_flags" do
        subject.tcp_flags.syn.should == 0
        subject.tcp_flags.psh.should == 0
        subject.tcp_flags.ack.should == 1
      end
    end

    context "when generating reflective bpf stubs" do
      before :each do
        @ack_pkt = @helper.get_tcp_packet()
        @ack_pkt.ip_saddr = "192.168.1.1"
        @ack_pkt.ip_daddr = "192.168.1.2"
        @ack_pkt.eth_saddr = "aa:aa:aa:aa:aa:aa"
        @ack_pkt.eth_daddr = "bb:bb:bb:bb:bb:bb"
        @ack_pkt.tcp_sport = 12345
        @ack_pkt.tcp_dport = 80
        @ack_pkt.tcp_flags.syn = 1
        @ack_pkt.tcp_flags.ack = 1
        @ack_pkt.tcp_seq = 11111
        @ack_pkt.tcp_ack = 22222
      end

      it "should generate the right bpf" do
        right_bpf =  "src 192.168.1.2 and " +
                     "dst 192.168.1.1 and " +
                     "src port 80 and " +
                     "dst port 12345"
      
        @helper.get_reflective_bpf(@ack_pkt).should == right_bpf
      end
    end

  end
end

