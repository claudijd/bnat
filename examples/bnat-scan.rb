$:.unshift File.join(File.dirname(__FILE__), '..', 'lib')

require 'optparse'
require 'ostruct'
require 'bnat'

options = OpenStruct.new
options.targets = []
options.ports = []
options.interface = "eth0"
options.fast = false

OptionParser.new do |opts|
  opts.banner = "Usage: rvmsudo ruby bnat_scan.rb [options]"

  opts.on("-t", "--targets [TARGETS]", "A list of IP/CIDR Blocks") do |t|
    options.targets << t
  end

  opts.on("-p", "--ports [PORTS]", "A list of ports to scan") do |p|
    options.ports << p
  end
  
  opts.on("-i", "--interface [INTERFACE]", "The interface to scan from") do |i|
    options.interface = i
  end
  
  opts.on("-f", "--[no-]fast", "just send syn's don't wait for responses") do |f|
    options.fast = f
  end

  opts.on_tail("-h", "--help", "Show this message") do
    puts ""
    puts opts
    puts ""
    puts "Example: rvmsudo ruby bnat-scan.rb -t 192.168.1.1 -p 80"
    puts ""
    exit
  end
end.parse!

Bnat::Scanner.new(
  :iface => options.interface,
  :ports => options.ports.collect {|p| p.to_i},
  :targets => options.targets,
  :fast => options.fast
).scan