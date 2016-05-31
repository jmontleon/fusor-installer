# = Fusor Network
#
# Configures networking according to values gathered by wizard, it does following actions
#   * configures gateway
#   * configures interface's IP address, netmask and DNS servers
#   * adds hosts record if missing
#   * configures firewall in a non-destructive way (leaves all existing rules untouched)
#
# === Parameters:
#
# $interface::            Which interface should this class configure
#
# $ip::                   What IP address should be set
#
# $netmask::              What netmask should be set
#
# $gateway::              What is the gateway for this machine
#
# $dns::                  DNS forwarder to use as secondary nameserver
#
# $configure_networking:: Should we modify networking?
#                         type:boolean
#
# $configure_firewall::   Should we modify firewall?
#                         type:boolean
#
class fusor_network(
    $interface,
    $ip,
    $netmask,
    $gateway,
    $dns,
    $configure_networking,
    $configure_firewall,
) {

  if ($configure_networking) {
    class { 'network::global':
      gateway => $gateway,
    }

    network::if::static { $interface:
      ensure    => 'up',
      ipaddress => $ip,
      netmask   => $netmask,
      dns1      => $ip,
      dns2      => $dns,
      peerdns   => true,
    }

  }

  if ($configure_firewall) {

    # The puppetlabs-firewall module does not currently support firewalld.
    # It also cannot handle clearing all the chains firewalld creates.
    # Starting iptables before firewalld is stopped also does not clean up properly.
    # Therefore, to get consistent results, we must methodically stop firewalld first.
    # Then stop iptables, save the blank policy, then create the new rules.
    class { 'firewall': }
    exec {'save-blank-policy':
      command => "service iptables stop; iptables-save > /etc/sysconfig/iptables",
      path    => "/usr/bin/:/usr/sbin/",
      require => Service['firewalld'],
      before  => Service['iptables'],
    } ->
    #Add standard rules to accept icmp, lo, and related/established traffic.
    firewall { '000 accept related established rules':
      proto   => 'all',
      state => ['RELATED', 'ESTABLISHED'],
      action  => 'accept',
    } ->
    firewall { '001 accept all icmp':
      proto   => 'icmp',
      action  => 'accept',
    } ->
    firewall { '001 accept all to lo interface':
      proto   => 'all',
      iniface => 'lo',
      action  => 'accept',
    } ->
    # The Foreman server should accept ssh connections for management.
    firewall { '22 accept - ssh':
      port   => '22',
      proto  => 'tcp',
      action => 'accept',
      state  => 'NEW',
    } ->
    # The Foreman server needs to accept DNS requests on this port for tcp and udp when provisioning systems.
    firewall { '53 accept - dns tcp':
      port   => '53',
      proto  => 'tcp',
      action => 'accept',
      state  => 'NEW',
    } ->
    firewall { '53 accept - dns udp':
      port   => '53',
      proto  => 'udp',
      action => 'accept',
      state  => 'NEW',
    } ->
    # The Foreman server needs to accept DHCP requests on this port when provisioning systems.
    firewall { '67 accept - dhcp':
      port   => '67',
      proto  => 'udp',
      action => 'accept',
      state  => 'NEW',
    } ->
    # The Foreman server needs to accept BOOTP requests on this port when provisioning systems.
    firewall { '68 accept - bootp':
      port   => '68',
      proto  => 'udp',
      action => 'accept',
      state  => 'NEW',
    } ->
    # The Foreman server needs to accept TFTP requests on this port when provisioning systems.
    firewall { '69 accept - tftp':
      port   => '69',
      proto  => 'udp',
      action => 'accept',
      state  => 'NEW',
    } ->
    # The Foreman web user interface accepts connections on these ports.
    firewall { '80 accept - apache':
      port   => '80',
      proto  => 'tcp',
      action => 'accept',
      state  => 'NEW',
    } ->
    # The Foreman server needs to accept NTP requests
    firewall { '123 accept - ntp':
      port   => '123',
      proto  => 'udp',
      action => 'accept',
    } ->

    firewall { '443 accept - apache':
      port   => '443',
      proto  => 'tcp',
      action => 'accept',
      state  => 'NEW',
    } ->
    # The Capsule accepts connections for provisioning on this port.
    firewall { '8000 accept - provisioning':
      port   => '8000',
      proto  => 'tcp',
      action => 'accept',
      state  => 'NEW',
    } ->
    # Candlepin listens on this port
    firewall { '8009 accept - provisioning':
      port   => '8009',
      proto  => 'tcp',
      action => 'accept',
      state  => 'NEW',
    } ->
    # The Foreman server accepts connections to Puppet on this port.
    firewall { '8140 accept - puppetmaster':
      port   => '8140',
      proto  => 'tcp',
      action => 'accept',
      state  => 'NEW',
    } ->
    # qpid-dispatch-routerd
    firewall { '5646 accept - managed systems':
      port   => '5646',
      proto  => 'tcp',
      action => 'accept',
      state  => 'NEW',
    } ->
    firewall { '5647 accept - managed systems':
      port   => '5647',
      proto  => 'tcp',
      action => 'accept',
      state  => 'NEW',
    } ->
    # The Foreman server accepts connections with managed systems on this port.
    firewall { '5671 accept - managed systems':
      port   => '5671',
      proto  => 'tcp',
      action => 'accept',
      state  => 'NEW',
    } ->
    firewall { '5672 accept - managed systems':
      port   => '5672',
      proto  => 'tcp',
      action => 'accept',
      state  => 'NEW',
    } ->
    # The Foreman server accepts connections to Tomcat on this port.
    firewall { '8080 accept - tomcat6':
      port   => '8080',
      proto  => 'tcp',
      action => 'accept',
      state  => 'NEW',
    } ->
    # The Capsule accepts connections to for subscription-manager on this port.
    firewall { '8443 accept - subscription-manager':
      port   => '8443',
      proto  => 'tcp',
      action => 'accept',
      state  => 'NEW',
    } ->
    # The Foreman server accepts connections to Smart Proxy on this port.
    firewall { '9090 accept - smart proxy':
      port   => '9090',
      proto  => 'tcp',
      action => 'accept',
      state  => 'NEW',
    } ->
    # This is for running the rails server on port 3000 in development mode
    firewall { '3000 accept - rails server':
      port   => '3000',
      proto  => 'tcp',
      action => 'accept',
      state  => 'NEW',
    } ->
    #Reject everything else
    firewall { '998 reject all':
      proto   => 'all',
      action  => 'reject',
    } ->
    firewall { '999 reject all forward':
      chain   => 'FORWARD',
      proto   => 'all',
      action  => 'reject',
    }
  }
}
