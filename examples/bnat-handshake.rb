$:.unshift File.join(File.dirname(__FILE__), '..', 'lib')

require 'optparse'
require 'ostruct'
require 'bnat'

options = OpenStruct.new
options.target = ""
options.port = 0
options.interface = "eth0"

OptionParser.new do |opts|
  opts.banner = "Usage: rvmsudo ruby bnat-handshake.rb [options]"

  opts.on("-t", "--target [TARGET]", "The IP of the system to test") do |t|
    options.target = t
  end

  opts.on("-p", "--port [PORT]", "The port to test") do |p|
    options.port = p
  end
  
  opts.on("-i", "--interface [INTERFACE]", "The interface to scan from") do |i|
    options.interface = i
  end

  opts.on_tail("-h", "--help", "Show this message") do
    puts ""
    puts opts
    puts ""
    puts "Example: rvmsudo ruby bnat-handshake.rb -t 192.168.1.1 -p 80"
    puts ""
    exit
  end
end.parse!

puts options.port

cf = Bnat::CaptureFactory.new(options.interface)
pf = Bnat::PacketFactory.new(options.interface)

bpf = "tcp and tcp[13] == 18"
pcap = cf.get_capture(bpf)

syn_pkt = pf.get_syn_probe(:ip => options.target, :port => options.port)
syn_pkt.recalc
syn_pkt.to_w
puts "sent the syn"

listen = Thread.new do
  loop do
    pcap.stream.each do |pkt|
      syn_ack_pkt = PacketFu::Packet.parse(pkt)

      puts "got the syn/ack"
      
      ack_pkt = pf.get_ack_probe()
      ack_pkt.ip_saddr = syn_ack_pkt.ip_daddr
      ack_pkt.ip_daddr = syn_ack_pkt.ip_saddr
      ack_pkt.eth_saddr = syn_ack_pkt.eth_daddr
      ack_pkt.eth_daddr = syn_ack_pkt.eth_saddr
      ack_pkt.tcp_sport = syn_ack_pkt.tcp_dport
      ack_pkt.tcp_dport = syn_ack_pkt.tcp_sport
      ack_pkt.tcp_ack = syn_ack_pkt.tcp_seq+1
      ack_pkt.tcp_seq = syn_ack_pkt.tcp_ack
      ack_pkt.tcp_win = 183
      ack_pkt.recalc
      ack_pkt.to_w
      
      puts "sent the ack"
    end
  end
end

listen.join