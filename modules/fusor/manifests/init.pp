# = Fusor
#
# Installs fusor package
#
# === Extra parameters:
#
# These parameters are not used for this class. They are placeholders for the installer
# so it can store values in answer file
#
# $configure_networking::   Should local networking be configured by installer?
#                           type:boolean
#
# $configure_firewall::     Should local firewall be configured by installer?
#                           type:boolean
#
# $interface::              Which interface should this class configure
#
# $ip::                     What IP address should be set
#
# $netmask::                What netmask should be set
#
# $own_gateway::            What is the gateway for this machine
#
# $dns::                    DNS forwarder to use as secondary nameserver
#
# $network::                Network address used when seeding subnet in Foreman
#
# $from::                   DHCP range first address, used for DHCP configuration and
#                           during Foreman subnet seeding
#
# $to::                     DHCP range last address, used for DHCP configuration and
#                           during Foreman subned seeding
#
# $lease_from::             First address used for Discovered Hosts
#
# $lease_to::               Last address used for Discovered Hosts
#
# $subnet_from::            First address used for Managed Hosts
#
# $subnet_to::              Last address used for Managed Hosts
#
# $domain::                 DNZ zone, used for DNS server configuration and during Foreman
#                           Domain seeding
#
# $fqdn::                   FQDN  of Foreman instance
#
# $gateway::                What is the gateway for machines using managed DHCP
#
# $ntp_host::               NTP sync host
#
# $timezone::               Timezone (IANA identifier)
#
# $root_password::          Default root password for provisioned machines
#                           type:password
#
# $foreman_admin_password:: Admin Password for Foreman
class fusor(
    $configure_networking = true,
    $configure_firewall = true,
    $interface,
    $ip,
    $netmask,
    $own_gateway,
    $gateway,
    $dns,
    $network,
    $from,
    $to,
    $lease_from,
    $lease_to,
    $subnet_from,
    $subnet_to,
    $domain,
    $fqdn,
    $ntp_host,
    $timezone,
    $root_password,
    $foreman_admin_password
) {
  validate_bool($configure_networking)

  # Configure NTP server
  class { '::ntp':
     servers => [$ntp_host],
     udlc => true,
     restrict => ['default nomodify notrap', '127.0.0.1', '::1'],
  }

  if $timezone {
    case $::osfamily {
      'RedHat': {
        if ($::operatingsystem == 'Fedora' or
           ($::operatingsystem != 'Fedora' and $::operatingsystemmajrelease > 6)) {
          # EL 7 variants and Fedora
          exec { 'set timezone':
            command => "/bin/timedatectl set-timezone $timezone",
          }
        } else {
          # EL 6 variants
          exec { 'ensure selected timezone exists':
            command => "/usr/bin/test -e /usr/share/zoneinfo/$timezone",
          }

          file { '/etc/localtime':
            ensure  => 'file',
            source  => "/usr/share/zoneinfo/$timezone",
            replace => true,
            require => Exec['ensure selected timezone exists'],
          }

          exec { 'set timezone in /etc/sysconfig/clock':
            command => "/bin/sed -ie 's|^ZONE=.*$|ZONE=\"$timezone\"|' /etc/sysconfig/clock",
            require => Exec['ensure selected timezone exists'],
          }
        }
      }
      default: {
        fail("${::hostname}: Setting timezone not supported on osfamily ${::osfamily}")
      }
    }
  }
}
