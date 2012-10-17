require 'packetfu'
require 'netaddr'
require 'optparse'
require 'ostruct'
require 'pp'

options = OpenStruct.new
options.targets = []
options.ports = []

OptionParser.new do |opts|
  opts.banner = "Usage: bnat_scan.rb [options]"

  opts.on("-t", "--targets [TARGETS]", "A list of IP/CIDR Blocks") do |t|
    options.targets << t
  end

  opts.on("-p", "--ports [PORTS]", "A list of ports to scan") do |p|
    options.ports << p
  end

  opts.on_tail("-h", "--help", "Show this message") do
    puts opts
    exit
  end
end.parse!

def get_packetfu_config
  begin
    packetfu_config = PacketFu::Utils.whoami?()
    return packetfu_config
  rescue => e
    puts e
    puts "Root access is required to perform a raw capture"
    exit
  end
end

def get_tcp_packet
  tcp_pkt = PacketFu::TCPPacket.new(
    :config=> get_packetfu_config,
    :timeout=> 0.1,
    :flavor=>"Windows"
  )
  tcp_pkt.tcp_flags.syn=1
  tcp_pkt.tcp_win=14600
  tcp_pkt.tcp_options="MSS:1460,SACKOK,TS:3853;0,NOP,WS:5"

  return tcp_pkt
end

def get_capture(bpf)
  PacketFu::Capture.new(
    :iface => get_packetfu_config[:iface],
    :start => true,
    :filter => "tcp and #{bpf}"
  )
end

def scan_ip(target,ports)
  tcp_pkt = get_tcp_packet
  tcp_pkt.ip_daddr = target

  ports.each do |port|
    tcp_pkt.tcp_dst = port.to_i
    tcp_pkt.tcp_src = rand(64511)+1024
    tcp_pkt.tcp_seq = rand(64511)+1024

    bpf =
      # debug (check for open port)
      #"host #{target} and tcp[13] == 18 and " +
      # live (check for bnat port)
      "not host #{target} and tcp[13] == 18 and " + 
      "tcp [8:4] == 0x#{(tcp_pkt.tcp_seq + 1).to_s(16)}"

    pcap = get_capture(bpf)

    scan = Thread.new do
      tcp_pkt.recalc
      tcp_pkt.to_w
      sleep 0.075
      tcp_pkt.to_w
    end

    analyze = Thread.new do
      loop do
        pcap.stream.each do |pkt|
          tcp_resp_pkt = PacketFu::Packet.parse(pkt)
          puts "[+] Discovered BNAT Service"
          sent_msg = tcp_pkt.ip_daddr.to_s + ":" + tcp_pkt.tcp_dst.to_s + "(" + tcp_pkt.tcp_seq.to_s + ")"
          recv_msg = tcp_resp_pkt.ip_saddr.to_s + ":" + tcp_resp_pkt.tcp_src.to_s + "(" + tcp_resp_pkt.tcp_ack.to_s + ")"
          puts sent_msg + " ==> " + recv_msg
          self.terminate
        end
      end
    end

    scan.join
    sleep 0.05
    analyze.terminate
  end
end

def run(options)

  if options.targets.size == 0
    puts "You need to specify targets with the -t flag"
    exit
  end

  if options.ports.size == 0
    puts "You need to specify ports with the -p flag"
    exit
  end

  options.targets.each do |target|
    begin
      cidr = NetAddr::CIDR.create(target)

      start = NetAddr::CIDR.create(cidr.first)
      fin = NetAddr::CIDR.create(cidr.last)

      (start..fin).each do |addr|
        scan_ip(addr.ip, options.ports)
      end
    rescue => e
      puts e
      puts "Failed to parse " + target + " as a CIDR target"
    end
  end
end

run(options)
