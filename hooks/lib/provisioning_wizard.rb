require 'resolv'
require 'ip'

class ProvisioningWizard < BaseWizard
  def self.attrs
    {
        :interface => 'Network interface',
        :ip => 'IP address',
        :fqdn => 'Hostname',
        :netmask => 'Network mask',
        :network => 'DHCP network address',
        :own_gateway => 'Host gateway',
        :from => 'DHCP range start',
        :to => 'DHCP range end',
        :gateway => 'DHCP gateway',
        :dns => 'DNS forwarder',
        :domain => 'Domain',
        :ntp_host => 'NTP sync host',
        :timezone => 'Time zone',
        :configure_networking => 'Configure networking',
        :configure_firewall => 'Configure firewall',
        :register_host => 'Register Host For Updates'
    }
  end

  def self.order
    %w(interface fqdn ip netmask own_gateway network from to gateway dns domain ntp_host timezone register_host configure_networking configure_firewall)
  end

  def self.custom_labels
    {}
  end

  attr_accessor *attrs.keys

  def initialize(kafo)
    super
    self.header = 'Networking setup:'
    self.help = "The installer can configure the networking and firewall rules on this machine with the configuration shown below. Default values are populated from this machine's existing networking configuration.\n\nIf you DO NOT want to configure networking, select 'Configure networking' and change the value to false."
    self.allow_cancellation = true

    @register_host = false
    @configure_networking = true
    @configure_firewall = true
  end

  def start
    begin
      get_interface if @interface.nil? || !interfaces.has_key?(@interface)
      super
    rescue Exception => e
      @kafo.logger.info ("Got interrupt, exiting installer.")
      @kafo.class.exit(:invalid_values)
    end
  end

  def get_configure_networking
    self.configure_networking = !configure_networking
  end

  def get_configure_firewall
    self.configure_firewall = !configure_firewall
  end

  def get_timezone
    @timezone = ask('Enter an IANA time zone identifier (e.g. America/New_York, Pacific/Auckland, UTC)')
  end

  def domain
    @domain ||= Facter.value :domain
  end

  def dns
    @dns ||= begin
      line = File.read('/etc/resolv.conf').split("\n").detect { |line| line =~ /nameserver\s+.*/ && ( line !~ /#{ip}\s*$/ || ip.nil? ) }
      line.split(' ').last || ''
    rescue
      ''
    end
  end

  def own_gateway
    if @own_gateway != nil && !@own_gateway.empty?
      @own_gateway
    elsif !`ip route | awk '/default/{print $3}'`.chomp.empty?
      @own_gateway = `ip route | awk '/default/{print $3}'`.chomp
    elsif ip != nil && netmask != nil && valid_ip?(ip)
      begin
        mask = get_pfx(netmask)
        addr = get_cidr(ip, mask)
        if addr == addr.network(1)
          @own_gateway = addr.broadcast(-1).to_addr
        else
          @own_gateway = addr.network(1).to_addr
        end
      rescue
      end
    end
  end

  def network
    if @network != nil && !@network.empty?
      @network
    elsif ip != nil && netmask != nil
      begin
        mask = get_pfx(netmask)
        addr = get_cidr(ip, mask)
        @network = addr.network.to_addr
      rescue
      end
    end
  end

  def gateway
    if @gateway != nil && !@gateway.empty?
      @gateway
    elsif own_gateway != nil && ip != nil && netmask != nil
      begin
        mask = get_pfx(netmask)
        addr = get_cidr(ip, mask)
        gw = get_cidr(own_gateway, mask)
        if gw.is_in?(addr.network)
          @gateway = own_gateway
        elsif addr == addr.network(1)
          @gateway = addr.broadcast(-1).to_addr
        else
          @gateway = addr.network(1).to_addr
        end
      rescue
      end
    end
  end

  def from
    if @from != nil && !@from.empty?
      @from
    elsif ip != nil && netmask != nil
      begin
        mask = get_pfx(netmask)
        addr = get_cidr(ip, mask)
        gw = get_cidr(gateway, mask)
        if gw < addr && (addr-gw) >= (addr.broadcast-addr) && (addr-gw) >= (gw-addr.network)
          @from = (gw+1).to_addr
        elsif gw < addr && (addr.broadcast-addr) >= (gw-addr.network)
          @from = (addr+1).to_addr
        elsif gw < addr
          @from = addr.network(1).to_addr
        elsif (gw-addr) >= (addr.broadcast-gw) && (gw-addr) >= (addr-addr.network)
          @from = (addr+1).to_addr
        elsif (addr.broadcast-gw) >= (addr-addr.network)
          @from = (gw+1).to_addr
        else
          @from = addr.network(1).to_addr
        end
      rescue
      end
    end
  end

  def to
    if @to != nil && !@to.empty?
      @to
    elsif ip != nil && netmask != nil
      begin
        mask = get_pfx(netmask)
        addr = get_cidr(ip, mask)
        gw = get_cidr(gateway, mask)
        if gw < addr && (addr-gw) >= (addr.broadcast-addr) && (addr-gw) >= (gw-addr.network)
          @to = (addr-1).to_addr
        elsif gw < addr && (addr.broadcast-addr) >= (gw-addr.network)
          @to = addr.broadcast(-1).to_addr
        elsif gw < addr
          @to = (gw-1).to_addr
        elsif (gw-addr) >= (addr.broadcast-gw) && (gw-addr) >= (addr-addr.network)
          @to = (gw-1).to_addr
        elsif (addr.broadcast-gw) >= (addr-addr.network)
          @to = addr.broadcast(-1).to_addr
        else
          @to = (addr-1).to_addr
        end
      rescue
      end
    end
  end

  def netmask=(mask)
    if mask.to_s.include?('/')
      mask_len = mask.split('/').last.to_i
      mask = IPAddr.new('255.255.255.255').mask(mask_len).to_s
    end
    @netmask = mask
  end

  def ntp_host
    @ntp_host ||= '0.rhel.pool.ntp.org'
  end

  def ip=(ip)
    @ip=ip
    config_fqdn
    @ip
  end

  def fqdn=(fqdn)
    @fqdn=fqdn
    @fqdn ||= Facter.value :fqdn
    config_fqdn
    if Facter.value('fqdn') != nil && Facter.value('fqdn') != 'localhost'
      @domain = Facter.value :domain
    end
    Facter.value :fqdn
  end

  def config_fqdn
    Facter.flush

    if @ip != nil && @fqdn != nil
      begin
        resolvedaddress = Resolv.getaddress(@fqdn)
      rescue
        resolvedaddress = nil
      end

      if resolvedaddress != @ip || "#{Facter.value :fqdn}" != "#{@fqdn}"
        result = system("/usr/bin/hostname #{@fqdn} 2>&1 >/dev/null")
        if $?.exitstatus > 0
          say "<%= color('Warning: Could not set hostname: #{result}', :bad) %>"
        end

        begin
          hosts = File.read('/etc/hosts')
          hosts.gsub!(/^#{Regexp.escape(@ip)}\s.*?$\n/, '')
          hosts.gsub!(/^.*?\s#{Regexp.escape(@fqdn)}\s.*?$\n/, '')
          hosts.chop!
          hosts += "\n#{@ip} #{@fqdn} #{Facter.value('hostname')}\n"
          File.open('/etc/hosts', "w") { |file| file.write(hosts) }
        rescue => error
          say "<%= color('Warning: Could not write host entry to /etc/hosts: #{error}', :bad) %>"
        end
        begin
          File.write('/etc/hostname', "#{@fqdn}")
        rescue  => error
          say "<%= color('Warning: Could not write hostname to /etc/hostname: #{error}', :bad) %>"
        end

        Facter.flush
        say "<%= color('Hostname configuration updated!', :good) %>"
      end
    end
  end

  def timezone
    @timezone ||= current_system_timezone
  end

  def system_registered?
    # returns true if consumer cert exists and resembles a certificate.
    # unregistered systems should not have /etc/consumer/cert.pem
    return system ('grep "BEGIN CERTIFICATE" /etc/pki/consumer/cert.pem &> /dev/null')
  end

  def get_register_host
    @register_host = !@register_host
    if @register_host
      @register_host = true
      say "<%= color('Register this host with subscription manager to the customer portal for updates', :info) %>"

      if system_registered?
        reregister_response = ask('System is already registered to the customer portal. Re-register? [Y/n] ')
        if ['n', 'N', 'no', 'NO', 'No'].include? reregister_response
          @register_host = false
          return
        else
          @register_host = true
        end
      end

      @portal_username = ask('Enter the USERNAME: ')
      begin
        password = ask('Enter the PASSWORD: ') { |q| q.echo = false }
        passwrd2 = ask(' Re-enter PASSWORD: ') { |q| q.echo = false }
      end while !password.eql?(passwrd2)
      @portal_password = password
    else
      @register_host = false # ensure it's a boolean
    end
  end

  def validate_interface
    'Interface must be specified' if @interface.nil? || @interface.empty?
  end

  def validate_ip
    if !(valid_ip?(@ip))
      'IP address is invalid'
    elsif !(valid_ip?(@to)) || !(valid_ip?(@from))
      # No need to repeat the Invalid IP message here
    elsif (IPAddr.new(from)..IPAddr.new(to))===IPAddr.new(ip)
      'DHCP range is Invalid - DHCP range includes the provisioning host IP address'
    end
  end

  def validate_netmask
    if netmask == nil
      'You must specify a netmask'
    elsif !(valid_ip?(@netmask))
      'Network mask is Invalid'
    elsif !(valid_ip?(@ip))
      # No need to repeat Invalid IP message here
    elsif get_cidr(@ip, get_pfx(netmask)).netmask.to_s != netmask
      'The netmask entered is not valid'
    elsif IPAddr.new(@netmask).to_i.to_s(2).count("1").to_i > 28
      'You require a /28 (255.255.255.240) subnet at minimum'
    end
  end

  def validate_network
    if !(valid_ip?(@network))
      'Network address - Invalid IP address'
    elsif !(valid_ip?(@to)) || !(valid_ip?(@from))
      # No need to repeat the Invalid IP message here
    elsif (IPAddr.new(from)..IPAddr.new(to))===IPAddr.new(network)
      'DHCP range is Invalid - DHCP range includes the Network address IP address'
    end
  end

  def validate_own_gateway
    if !(valid_ip?(@own_gateway))
      'Host Gateway - Invalid IP address'
    elsif !(valid_ip?(@to)) || !(valid_ip?(@from))
      # No need to repeat the Invalid IP message here
    elsif (IPAddr.new(from)..IPAddr.new(to))===IPAddr.new(own_gateway)
      'DHCP range is Invalid - DHCP range includes the Host Gateway IP address'
    end
  end

  def validate_from
    if !(valid_ip?(@ip))
      # No need to repeat the Invalid IP message here
    elsif !(valid_ip?(@from))
      'DHCP range start - Invalid IP address'
    elsif !(valid_ip?(@to))
      # No need to repeat the Invalid IP message here
    elsif IPAddr.new(from).to_i > IPAddr.new(to).to_i
      'DHCP range start is Invalid - DHCP range start is greater than DHCP range end'
    end
  end

  def validate_to
    if !(valid_ip?(@ip))
      # No need to repeat the Invalid IP message here
    elsif !(valid_ip?(@to))
      'DHCP range end - Invalid IP address'
    elsif !(valid_ip?(@from))
      # No need to repeat the Invalid IP message here
    elsif IPAddr.new(to).to_i < (IPAddr.new(from).to_i)+1
      'DHCP range end is Invalid - Minimum range of 2 needed from DHCP range start'
    end
  end

  def validate_gateway
    if !(valid_ip?(@ip))
      # No need to repeat the Invalid IP message here
    elsif !(valid_ip?(@gateway))
      'DHCP Gateway - Invalid IP address'
    elsif IPAddr.new(ip)===IPAddr.new(gateway)
      'DHCP Gateway conflicts with the IP address of the provisioning host'
    elsif !(valid_ip?(@to)) || !(valid_ip?(@from))
      # No need to repeat the Invalid IP message here
    elsif (IPAddr.new(from)..IPAddr.new(to))===IPAddr.new(gateway)
      'DHCP range is Invalid - DHCP range includes the DHCP Gateway IP address'
    end
  end

  def validate_dns
    if !(valid_ip?(@dns))
      'DNS forwarder - Invalid IP address'
    elsif to != nil && from != nil && valid_ip?(@to) && valid_ip?(@from) && (IPAddr.new(from)..IPAddr.new(to))===IPAddr.new(dns)
      'DHCP range is Invalid - DHCP range includes the DNS forwarder IP address'
    end
  end

  def validate_fqdn
    'Hostname must be specified' if @hostname.nil? || @hostname.empty?
    if @fqdn =~ /[A-Z]/
      'Invalid hostname. Uppercase characters are not supported.'
    elsif @fqdn !~ /\./
      'Invalid hostname. Must include at least one dot.'
    elsif @fqdn !~ /^(?=.{1,255}$)[0-9a-z](?:(?:[0-9a-z]|-){0,61}[0-9a-z])?(?:\.[0-9a-z](?:(?:[0-9a-z]|-){0,61}[0-9a-z])?)*\.?$/
      'Invalid hostname.'
    end
  end

  def validate_domain
    'Domain must be specified' if @domain.nil? || @domain.empty?
  end

  def validate_ntp_host
    if @ntp_host.nil? || @ntp_host.empty?
      'NTP sync host must be specified'
    elsif !(valid_hostname?(@ntp_host))  && !(valid_hostname?(@ntp_host))
      'NTP sync host - Invalid Hostname or IP address'
    end
  end

  def validate_timezone
    'Time zone is not a valid IANA time zone identifier' unless valid_timezone?(@timezone)
  end

  def portal_username
    return @portal_username
  end

  def portal_password
    return @portal_password
  end

  private

  def get_interface
    case interfaces.size
      when 0
        HighLine.color("\nFacter didn't find any NIC, can not continue", :bad)
        raise StandardError
      when 1
        @interface = interfaces.keys.first
      else
        @interface = choose do |menu|
          menu.header = "\nSelect which NIC to use for provisioning"
          interfaces.keys.sort.each do |nic|
            menu.choice("#{nic} (#{interfaces[nic][:macaddress]})") { nic }
          end
        end
    end

    setup_networking
  end

  def setup_networking
    @ip = interfaces[@interface][:ip]
    @network = interfaces[@interface][:network]
    @netmask = interfaces[@interface][:netmask]
    @cidr = interfaces[@interface][:cidr]
  end

  def interfaces
    @interfaces ||= (Facter.value :interfaces || '').split(',').reject { |i| i == 'lo' }.inject({}) do |ifaces, i|
      ip = Facter.value "ipaddress_#{i}"
      network = Facter.value "network_#{i}"
      netmask = Facter.value "netmask_#{i}"
      macaddress = Facter.value "macaddress_#{i}"

      cidr, from, to = nil, nil, nil
      if ip && network && netmask
        cidr = "#{network}/#{IPAddr.new(netmask).to_i.to_s(2).count('1')}"
      end

      ifaces[fix_interface_name(i)] = {:ip => ip, :netmask => netmask, :network => network, :cidr => cidr, :from => from, :to => to, :gateway => gateway, :macaddress => macaddress}
      ifaces
    end
  end

  def get_cidr(ip, mask)
    IP.new("#{ip}/#{mask}")
  end

  def get_pfx(netmask)
    IPAddr.new(netmask).to_i.to_s(2).count("1")
  end

  # facter can't distinguish between alias and vlan interface so we have to check and fix the eth0_0 name accordingly
  # if it's a vlan, the name should be eth0.0, otherwise it's alias and the name is eth0:0
  # if both are present (unlikly) facter overwrites attriutes and we can't fix it
  def fix_interface_name(facter_name)
    if facter_name.include?('_')
      ['.', ':'].each do |separator|
        new_facter_name = facter_name.tr('_', separator)
        return new_facter_name if system("ifconfig #{new_facter_name} &> /dev/null")
      end

      # if ifconfig failed, we fallback to /sys/class/net detection, aliases are not listed there
      new_facter_name = facter_name.tr('_', '.')
      return new_facter_name if File.exists?("/sys/class/net/#{new_facter_name}")
    end
    facter_name
  end

  def valid_ip?(ip)
    IPAddr.new(ip)
    true
  rescue
    false
  end

  def valid_hostname?(hostname)
    (!!(hostname =~ Resolv::IPv4::Regex)) ||
    (!!(hostname =~ Resolv::IPv6::Regex)) ||
    (hostname =~ /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/)
  end

  # NOTE(jistr): currently we only have tzinfo for ruby193 scl and
  # this needs to run on system ruby, so i implemented a custom
  # timezone validation (not extremely strict - it's not filtering
  # zoneinfo subdirectories etc., but it should catch typos well,
  # which is what we care about)
  def valid_timezone?(timezone)
    zoneinfo_file_names = %x(/bin/find /usr/share/zoneinfo -type f).lines
    zones = zoneinfo_file_names.map { |name| name.strip.sub('/usr/share/zoneinfo/', '') }
    zones.include? timezone
  end

  def current_system_timezone
    if File.exists?('/usr/bin/timedatectl')  # systems with systemd
      # timezone_line will be like 'Timezone: Europe/Prague (CEST, +0200)'
      timezone_line = %x(/usr/bin/timedatectl status | grep "Time zone: ").strip
      return timezone_line.match(/Time zone: ([^ ]*) /)[1]
    else  # systems without systemd
      # timezone_line will be like 'ZONE="Europe/Prague"'
      timezone_line = %x(/bin/cat /etc/sysconfig/clock | /bin/grep '^ZONE=').strip
      # don't rely on single/double quotes being present
      return timezone_line.gsub('ZONE=', '').gsub('"','').gsub("'",'')
    end
  rescue StandardError => e
    # Don't allow this function to crash the installer.
    # Worst case we'll just return UTC.
    @logger.debug("Exception when getting system time zone: #{e.message}")
    return 'UTC'
  end
end
