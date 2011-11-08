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

puts "\nbnat-pcap.rb v0.3\n"

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
last = Time.now

pcap = PacketFu::PcapFile.new.f2a(
  :f => "./synack.pcap",
  :filter => "tcp and tcp[13] == 18"
)

puts "SYN/ACK PCAP Load time was #{Time.now - last} seconds"
last = Time.now

pcap.each do |pkt|
  packet = PacketFu::Packet.parse(pkt)
  synack_hash = {
    "ip" => packet.ip_saddr.to_s,
    "sport" => packet.tcp_sport.to_s,
    "seq" => packet.tcp_ack.to_s,
    "dport" => packet.tcp_dport.to_s
  }
  synackarray.push(synack_hash)
end

synackarray = synackarray.uniq

#Build BPF so we can focus on just SYN's that have a matching seq
bpf = ""
temp = ""
temp2 = 0
synackarray.each do |synack|
  temp = synack["seq"]
  temp2 = temp.to_i-1
  if bpf == ""
    bpf = "'tcp[4:4] == 0x"+temp2.to_s(16)+"'"
  else
    bpf += " or 'tcp[4:4] == 0x"+temp2.to_s(16)+"'"
  end
end

#Build BPF so we can focus on just SYN's that have a matching src port
bpf2 = ""
synackarray.each do |synack|
  temp3 = synack["dport"].to_i
  if bpf2 == ""
    bpf2 = "'tcp[0:2] == 0x"+temp3.to_s(16)+"'"
  else
    bpf2 += " or 'tcp[0:2] == 0x"+temp3.to_s(16)+"'"
  end
end

#Mark our SYN/ACK PCAP Process Start
puts "SYN/ACK PCAP Process time was #{Time.now - last} seconds"
last = Time.now

#Scrap our SYN's that have matching SEQ's to our SYN/ACK array
puts "\nParsing SYN data from PCAP based on SYN/ACK SEQ matches..."
system("tcpdump -nn -r #{sample} -w ./syn.pcap 'tcp[13] == 2' and #{bpf}")

#Scrap our SYN's that have matching SRC ports to our SYN/ACK array
puts "Parsing SYN data from PCAP based on SYN/ACK src port matches..."
system("tcpdump -nn -r #{sample} -w ./syn2.pcap 'tcp[13] == 2' and #{bpf2}")

#Mark our SYN/ACK PCAP Process Completion
puts "Parsed SYN data from PCAP in #{Time.now - last} seconds"
last = Time.now

#Load the pcaps of SYN's we scraped out
pcap2 = PacketFu::PcapFile.new.f2a(:f => './syn.pcap')
pcap3 = PacketFu::PcapFile.new.f2a(:f => './syn2.pcap')

#Combine and de-dup our SYN's to speed up process time later
pcap4 = (pcap2 + pcap3).uniq

#Mark our SYN PCAP load completion
puts "SYN PCAP Load time was #{Time.now - last} seconds"
last = Time.now

#For Each SYN, index it into a usable hash for comparison
pcap4.each do |pkt|
  packet = PacketFu::Packet.parse(pkt)
  syn_hash = {
    "ip" => packet.ip_daddr.to_s,
    "dport" => packet.tcp_dport.to_s,
    "seq" => packet.tcp_seq.to_s,
    "sport" => packet.tcp_sport.to_s
  }
  synarray.push(syn_hash)
end

#Mark our process time
puts "SYN PCAP Process time was #{Time.now - last} seconds\n\n"
last = Time.now

#synarray = synarray.uniq

#Loop through each SYN/ACK and compare to each SYN
synackarray.each do |synackpacket|
  synarray.each do |synpacket|
    temp = synpacket["seq"]
    temp2 = temp.to_i
    tempseq = temp2+1
    
    ip, dport, sport, seq = false, false, false, false
    
    ip = true if synackpacket["ip"] == synpacket["ip"]
    dport = true if synackpacket["dport"] == synpacket["sport"]
    sport = true if synackpacket["sport"] == synpacket["dport"]
    seq = true if synackpacket["seq"] == tempseq.to_s
    
    if !ip and dport and sport and seq
      puts "IP Based BNAT Detected:"
      puts "Request:  #{synpacket}"
      puts "Response: #{synackpacket}"
    end
    
    if ip and dport and !sport and seq
      puts "Source Port Based BNAT Detected:"
      puts "Request:  #{synpacket}"
      puts "Response: #{synackpacket}"
    end
    
    if ip and dport and sport and !seq
      puts "Sequence Number Based BNAT Detected:"
      puts "Request:  #{synpacket}"
      puts "Response: #{synackpacket}"
    end
    
    if !ip and dport and !sport and seq
      puts "IP and Source Port Based BNAT Detected:"
      puts "Request:  #{synpacket}"
      puts "Response: #{synackpacket}"
    end
  end
end

#Mark our end to end process time
puts "\nTime elapsed #{Time.now - beginning} seconds\n\n"

system("rm syn.pcap syn2.pcap synack.pcap")