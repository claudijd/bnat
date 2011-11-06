#bnat-pcap - A tool to passively detect BNAT in static pcap files
#
#Jonathan Claudius
#Copyright (C) 2011 Trustwave
#
#This program is free software: you can redistribute it and/or modify it under
#the terms of the GNU General Public License as published by the Free Software
#Foundation, either version 3 of the License, or (at your option) any later
#version.
#
#This program is distributed in the hope that it will be useful, but WITHOUT
#ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
#FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License along with
#this program. If not, see <http://www.gnu.org/licenses/>.

require 'rubygems'
require 'packetfu'

synack_hash = Hash.new
synackarray = Array.new
syn_hash = Hash.new
synarray = Array.new

puts "\nbnat-pcap.rb v0.2\n\n"

def usage
  puts "\nUsage: ruby ./bnat-pcap.rb <packetcapture>.pcap\n\n"
  exit
end

if ARGV.length != 1 or not File.exist?(ARGV[0])
  usage()
end

sample = ARGV[0]

beginning = Time.now

puts "\nParsing SYN/ACK data from PCAP..."
system("tcpdump -nn -r #{sample} -w ./synack.pcap tcp[13] == 18")
puts "Parsed SYN/ACK data from PCAP in #{Time.now - beginning} seconds"

pcap = PcapFile.new.f2a( :f => "./synack.pcap", :filter => "tcp and tcp[13] == 18")

puts "SYN/ACK PCAP Load time was #{Time.now - beginning} seconds"

pcap.each do |pkt|
  packet = PacketFu::Packet.parse(pkt)
  synack_hash = { "ip" => packet.ip_saddr.to_s, "port" => packet.tcp_sport.to_s, "seq" => packet.tcp_ack.to_s}
  synackarray.push(synack_hash)
end

synackarray = synackarray.uniq

bpf = ""
temp = ""
temp2 = 0
synackarray.each do |synack|
  temp = synack["seq"]
  temp2 = temp.to_i-1
  if bpf == ""
    bpf = "'tcp [4:4] == 0x"+temp2.to_s(16)+"'"
  else
    bpf = bpf+" or 'tcp [4:4] == 0x"+temp2.to_s(16)+"'"
  end
end

puts "BPF: "+bpf

puts "SYN/ACK PCAP Process time was #{Time.now - beginning} seconds"

puts "\nParsing SYN data from PCAP..."
system("tcpdump -nn -r #{sample} -w ./syn.pcap 'tcp[13] == 2' and #{bpf}")
puts "Parsed SYN data from PCAP in #{Time.now - beginning} seconds"

pcap2 = PcapFile.new.f2a(:f => './syn.pcap')

puts "SYN PCAP Load time was #{Time.now - beginning} seconds"

pcap2.each do |pkt|
  packet = PacketFu::Packet.parse(pkt)
  syn_hash = { "ip" => packet.ip_daddr.to_s, "port" => packet.tcp_dport.to_s, "seq" => packet.tcp_seq.to_s}
  synarray.push(syn_hash)
  #puts "[+]SYN:\t\t"+packet.ip_daddr.to_s+"\t"+packet.tcp_dport.to_s+"\t"+packet.tcp_seq.to_s
end

puts "SYN PCAP Process time was #{Time.now - beginning} seconds\n\n"

synarray = synarray.uniq

synackarray.each do |synackpacket|
  synarray.each do |synpacket|
    temp = synpacket["seq"]
    temp2 = temp.to_i
    seq = temp2+1
    if synackpacket["ip"] != synpacket["ip"] and synackpacket["port"] == synpacket["port"] and synackpacket["seq"] == seq.to_s
      puts "[+]BNAT DETECTED:\t Requested:"+synpacket["ip"]+":"+synpacket["port"]+"\t Responded:"+synackpacket["ip"]+":"+synackpacket["port"]+"\tSession:"+seq.to_s
    end
  end
end

puts "\nTime elapsed #{Time.now - beginning} seconds\n\n"

system("rm syn.pcap synack.pcap")
