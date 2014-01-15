module BNAT

  class IPFW
    def initialize(path)
      @path = path
      @rules_added = []
    end

    def rules
      `ipfw list`.chomp.split("\n")
    end

    def suppress_rsts(ip, opts = {})
      ret = `ipfw add deny tcp from #{ip} to any tcpflags rst`.chomp

      if match = ret.match(/^(\d+)/)
        @rules_added << match[1]
      else
        raise "Failed to add rule: #{ret}"
      end
    end

    def remove_rules
      @rules_added.each do |rule|
        `ipfw delete #{rule}`
      end

      @rules_added = []

      return rules
    end
  end

  class IPTables
    def initialize(path)
      @path = path
      @rules_added = []
    end

    def rules
      # TODO: implement this
      raise "Not implemented yet, sorry"
    end

    def suppress_rsts(ip, opts = {})
      `iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP`.chomp
    end

    def remove_rules
      # TODO: implement this      
      raise "Not implemented yet, sorry"
    end
  end
    
  class Firewall
    def initialize(opts = {})
      @firewall = opts[:firewall] || detect_firewall
    end

    def detect_firewall
      ipfw_path = `which ipfw`.chomp
      iptables_path = `which iptables`.chomp

      if ipfw_path.size > 0
        return BNAT::IPFW.new(ipfw_path)
      elsif iptables_path.size > 0
        return BNAT::IPFW.new(iptables_path)
      else
        raise "Unable to detect firewall (ipfw/iptables)"
      end
    end

    def suppress_rsts(ip = PacketFu::Utils.default_ip)
      @firewall.suppress_rsts(ip)
    end

    def rules
      @firewall.rules
    end

    def remove_rules
      @firewall.remove_rules
    end
  end
end
