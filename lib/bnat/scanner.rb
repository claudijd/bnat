require 'packetfu'
require 'netaddr'
require 'bnat'
require 'pp'

# A class for performing BNAT Scanning

module Bnat 
  class Scanner
    
    attr_accessor :iface, :ports, :targets

    # @param opts [String] :iface - a string of the interface name
    # @param opts [Array] :ports - an array of ports to scan
    # @param opts [Array] :targets - an array of ports to scan
    # @param opts [String] :mode - the mode run the scan as ("normal"/"fast")
    def initialize(opts = {})
      @iface = opts[:iface]
      @ports = opts[:ports]
      @targets = opts[:targets]
      @pf = Bnat::PacketFactory.new(@iface)
      @cf = Bnat::CaptureFactory.new(@iface)
      @fast = opts[:fast] || false
    end
    
    # @param [String] a string IP to scan
    def scan_ip(ip)
      ret = []
        
      @ports.each do |port|
          
        #Generate a syn probe
        syn_pkt = @pf.get_syn_probe(:ip => ip, :port => port)
                
        #Define a BPF filter for responses
        bpf = # debug (check for open port)
              #"tcp and host #{ip} and tcp[13] == 18 and " +
              # live (check for bnat port)
              "tcp and not host #{ip} and tcp[13] == 18 and " + 
              "tcp [8:4] == 0x#{(syn_pkt.tcp_seq + 1).to_s(16)}"
        
        #Create a Capture to look for responses
        pcap = @cf.get_capture(bpf)
        
        #Send the Packet to the Wire
        scan = Thread.new do
          syn_pkt.recalc
          syn_pkt.to_w
          sleep 0.075
          syn_pkt.to_w
        end
        
        if @fast == false
          #Analyze Packets on the Wire for Matches
          analyze = Thread.new do
            loop do
              pcap.stream.each do |pkt|
                syn_ack_pkt = PacketFu::Packet.parse(pkt)
                
                ret << {
                  :sent => syn_pkt,
                  :recv => syn_ack_pkt
                }
  
                self.terminate
              end
            end
          end
        end
        
        scan.join
        
        if @fast == false
          sleep 0.05
          analyze.terminate
        end
      end
      
      return ret
    end
    
    def scan
      @targets.each do |target|
        
        cidr = NetAddr::CIDR.create(target)
        
        if cidr.size == 0
          puts "No addresses within provided target '#{target}'"  
        else
          start = NetAddr::CIDR.create(cidr.first)
          fin = NetAddr::CIDR.create(cidr.last)
          
          (start..fin).each do |addr|
            scan_ip(addr.ip).each do |bnat|
              report(bnat[:sent],  bnat[:recv])
            end
          end
        end
        
      end
    end
    
    # @param [PacketFu::Packet] the packet that was sent
    # @param [PacketFu::Packet] the packet that was received
    def report(sent, recv)
      sent_msg = sent.ip_daddr + ":" + sent.tcp_dst.to_s + "(" + sent.tcp_seq.to_s + ")"
      recv_msg = recv.ip_saddr + ":" + recv.tcp_src.to_s + "(" + recv.tcp_ack.to_s + ")"
      
      puts "[+] BNAT Detected"
      puts sent_msg + " ==> " + recv_msg
    end

  end
end