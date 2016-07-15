if app_value(:provisioning_wizard) != 'none'
  require File.join(KafoConfigure.root_dir, 'hooks', 'lib', 'base_wizard.rb')
  require File.join(KafoConfigure.root_dir, 'hooks', 'lib', 'provisioning_wizard.rb')
  provisioning_wizard = ProvisioningWizard.new(kafo)
  provisioning_wizard.start

  if provisioning_wizard.configure_networking || provisioning_wizard.configure_firewall
    command = PuppetCommand.new(%Q(class {"fusor_network":
      interface            => "#{provisioning_wizard.interface}",
      ip                   => "#{provisioning_wizard.ip}",
      netmask              => "#{provisioning_wizard.netmask}",
      gateway              => "#{provisioning_wizard.own_gateway}",
      dns                  => "#{provisioning_wizard.dns}",
      configure_networking => #{provisioning_wizard.configure_networking},
      configure_firewall   => #{provisioning_wizard.configure_firewall},
    }))
    command.append '2>&1'
    command = command.command

    say 'Starting networking setup'
    logger.debug "running command to set networking"
    logger.debug `#{command}`

    if $?.success?
      say 'Networking setup has finished'
    else
      say "<%= color('Networking setup failed', :bad) %>"
      kafo.class.exit(101)
    end

    if !system("ntpdate -q #{provisioning_wizard.ntp_host} &> /dev/null")  
      say HighLine.color("WARNING!! - NTP sync host \"#{provisioning_wizard.ntp_host}\" does not appear to be valid!", :bad)
      say HighLine.color('Do you want to continue anyway? [Yes/No]', :run)
      response = STDIN.gets
      if (response.downcase.chomp == "yes") || (response.downcase.chomp == "y") 
        say "  ... continuing installation"
      else
        say "Exiting installation!"
        logger.error "NTP sync host \"#{provisioning_wizard.ntp_host}\" is INVALID! ... Exiting"
        kafo.class.exit(:invalid_values)
      end
    else
      system("/bin/systemctl stop ntpd; /usr/sbin/ntpdate #{provisioning_wizard.ntp_host} >/dev/null")
      say HighLine.color('NTP sync host is ok', :good)
    end
  end

  #If a new admin password was specified set it, otherwise use the old value (if one exists).
  if app_value(:foreman_admin_password)
    param('fusor', 'foreman_admin_password').value = app_value(:foreman_admin_password)
  end

  param('fusor', 'configure_networking').value = provisioning_wizard.configure_networking
  param('fusor', 'configure_firewall').value = provisioning_wizard.configure_firewall
  param('fusor', 'interface').value = provisioning_wizard.interface
  param('fusor', 'ip').value = provisioning_wizard.ip
  param('fusor', 'netmask').value = provisioning_wizard.netmask
  param('fusor', 'own_gateway').value = provisioning_wizard.own_gateway
  param('fusor', 'gateway').value = provisioning_wizard.gateway
  param('fusor', 'dns').value = provisioning_wizard.dns
  param('fusor', 'network').value = provisioning_wizard.network
  param('fusor', 'from').value = provisioning_wizard.from
  param('fusor', 'to').value = provisioning_wizard.to
  param('fusor', 'domain').value = provisioning_wizard.domain
  param('fusor', 'fqdn').value = provisioning_wizard.fqdn
  param('fusor', 'ntp_host').value = provisioning_wizard.ntp_host
  param('fusor', 'timezone').value = provisioning_wizard.timezone

  #Write Satellite Configuration
  c = {}
  c['capsule'] = {}
  c['capsule']['parent_fqdn'] = provisioning_wizard.fqdn
  c['capsule']['parent_fqdn'] = provisioning_wizard.fqdn
  c['capsule']['pulp_master'] = true
  c['capsule']['puppet'] = true
  c['capsule']['qpid_router_broker_addr'] = provisioning_wizard.fqdn
  c['capsule']['register_in_foreman'] = true
  c['capsule']['templates'] = false
  c['certs'] = {}
  c['certs']['ca_common_name'] = provisioning_wizard.fqdn
  c['certs']['deploy'] = true
  c['certs']['generate'] = true
  if app_value(:devel_env)
    c['certs']['group'] = 'vagrant'
  else
    c['certs']['group'] = 'foreman'
  end
  c['certs']['node_fqdn'] = provisioning_wizard.fqdn
  unless app_value(:devel_env)
    c['foreman'] = {}
    if param('fusor', 'foreman_admin_password').value
     c['foreman']['admin_password'] = param('fusor', 'foreman_admin_password').value
    end
    c['foreman']['configure_epel_repo'] =  false
    c['foreman']['configure_scl_repo'] = false
    c['foreman']['custom_repo'] =  true
    c['foreman']['initial_organization'] = 'Default Organization'
    c['foreman']['initial_location'] = 'Default Location'
    c['foreman']['locations_enabled'] =  true
    c['foreman']['organizations_enabled'] = true
    c['foreman']['passenger_ruby'] = '/usr/bin/tfm-ruby'
    c['foreman']['passenger_ruby_package'] = 'tfm-rubygem-passenger-native'
    c['foreman']['ssl'] = true
    c['foreman']['server_ssl_cert'] = '/etc/pki/katello/certs/katello-apache.crt'
    c['foreman']['server_ssl_key'] = '/etc/pki/katello/private/katello-apache.key'
    c['foreman']['server_ssl_ca'] = '/etc/pki/katello/certs/katello-default-ca.crt'
    c['foreman']['server_ssl_chain'] = '/etc/pki/katello/certs/katello-default-ca.crt'
    c['foreman']['server_ssl_crl'] = false
    c['foreman']['websockets_encrypt'] = true
    c['foreman']['websockets_ssl_key'] = '/etc/pki/katello/private/katello-apache.key'
    c['foreman']['websockets_ssl_cert'] = '/etc/pki/katello/certs/katello-apache.crt'
    c['foreman']['servername'] = provisioning_wizard.fqdn
    c['foreman']['foreman_url'] = "https://#{provisioning_wizard.fqdn}"
    c['foreman']['repo'] = 'nightly'
  end
  c['foreman_proxy'] = {}
  c['foreman_proxy']['custom_repo'] = true
  c['foreman_proxy']['dhcp'] = true
  c['foreman_proxy']['dhcp_interface'] = provisioning_wizard.interface
  c['foreman_proxy']['dhcp_gateway'] = provisioning_wizard.gateway
  c['foreman_proxy']['dhcp_nameservers'] = provisioning_wizard.ip
  c['foreman_proxy']['dhcp_range'] = "#{provisioning_wizard.from} #{provisioning_wizard.to}"
  c['foreman_proxy']['dns'] = true
  c['foreman_proxy']['dns_forwarders'] = provisioning_wizard.dns
  c['foreman_proxy']['dns_interface'] = provisioning_wizard.interface
  c['foreman_proxy']['dns_reverse'] = provisioning_wizard.ip.split('.')[0..2].reverse.join('.') + '.in-addr.arpa'
  c['foreman_proxy']['dns_tsig_principal'] = "foremanproxy/#{provisioning_wizard.fqdn}@#{provisioning_wizard.domain.upcase}"
  c['foreman_proxy']['dns_zone'] = provisioning_wizard.domain
  c['foreman_proxy']['foreman_base_url'] = "https://#{provisioning_wizard.fqdn}"
  c['foreman_proxy']['foreman_ssl_ca'] = '/etc/foreman-proxy/foreman_ssl_ca.pem'
  c['foreman_proxy']['foreman_ssl_cert'] = '/etc/foreman-proxy/foreman_ssl_cert.pem'
  c['foreman_proxy']['foreman_ssl_key'] = '/etc/foreman-proxy/foreman_ssl_key.pem'
  c['foreman_proxy']['http'] = true
  c['foreman_proxy']['http_port'] = "8000"
  c['foreman_proxy']['pulp_master'] = true
  c['foreman_proxy']['puppet'] = true
  c['foreman_proxy']['puppetca'] = true
  c['foreman_proxy']['puppet_ssl_cert'] = "/var/lib/puppet/ssl/certs/#{provisioning_wizard.fqdn}.pem"
  c['foreman_proxy']['puppet_ssl_key'] = "/var/lib/puppet/ssl/private_keys/#{provisioning_wizard.fqdn}.pem"
  c['foreman_proxy']['puppet_url'] = "https://#{provisioning_wizard.fqdn}:8140"
  c['foreman_proxy']['realm_principal'] = "realm-proxy@#{provisioning_wizard.domain.upcase}"
  c['foreman_proxy']['registered_name'] = provisioning_wizard.fqdn
  c['foreman_proxy']['ssl_ca'] = '/etc/foreman-proxy/ssl_ca.pem'
  c['foreman_proxy']['ssl_cert'] = '/etc/foreman-proxy/ssl_cert.pem'
  c['foreman_proxy']['ssl_key'] = '/etc/foreman-proxy/ssl_key.pem'
  c['foreman_proxy']['ssl_port'] = "9090"
  c['foreman_proxy']['templates'] = true
  c['foreman_proxy']['template_url'] = "http://#{provisioning_wizard.fqdn}:8000"
  c['foreman_proxy']['tftp'] = true
  c['foreman_proxy']['tftp_dirs'] = ['/var/lib/tftpboot/pxelinux.cfg', '/var/lib/tftpboot/boot']
  c['foreman_proxy']['tftp_root'] = '/var/lib/tftpboot'
  c['foreman_proxy']['tftp_servername'] = provisioning_wizard.ip
  c['foreman_proxy']['trusted_hosts'] = [provisioning_wizard.fqdn]
  if app_value(:devel_env)
    c['katello_devel'] = {}
    c['katello_devel']['deployment_dir'] = '/home/vagrant'
    c['katello_devel']['user'] = 'vagrant'
    c['katello_devel']['rvm'] = true
    c['katello_devel']['db_type'] = 'postgres'
    if app_value(:deployment_dir)
      c['katello_devel']['deployment_dir'] = app_value(:deployment_dir)
    end
  else
    c['katello'] = {}
    c['katello']['package_names'] = ['katello', 'tfm-rubygem-katello']
    c["foreman::plugin::bootdisk"] = true
    c["foreman::plugin::chef"] = false
    c["foreman::plugin::default_hostgroup"] = false
    c["foreman::plugin::discovery"] = true
    c["foreman::plugin::hooks"] = true
    c["foreman::plugin::puppetdb"] = false
    c["foreman::plugin::remote_execution"] = false
    c["foreman::plugin::setup"] = false
    c["foreman::plugin::tasks"] = true
    c["foreman::plugin::templates"] = false
  end
  c["foreman_proxy::plugin::pulp"] = {}
  c["foreman_proxy::plugin::pulp"]['enabled'] = true
  c["foreman_proxy::plugin::pulp"]['pulpnode_enabled'] = false
  c["foreman_proxy::plugin::pulp"]['pulp_url'] = "https://#{provisioning_wizard.fqdn}/pulp"

  File.open('/etc/foreman-installer/scenarios.d/fusor.answers.yaml', 'w') {|f| f.write c.to_yaml }

  d=YAML::load(File.open('/etc/fusor-installer/fusor-scenario.template'))
  if app_value(:devel_env)
    d[:log_level] = 'DEBUG'
    d[:hook_dirs] = []
    d[:order] = ['certs', 'katello_devel', 'foreman_proxy', 'capsule']
  end
  file = File.open('/etc/foreman-installer/scenarios.d/fusor.yaml', 'w') {|f| f.write d.to_yaml }

end
