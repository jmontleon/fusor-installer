require 'ipaddr'

class ProvisioningSeeder < BaseSeeder
  attr_accessor :domain, :fqdn

  def initialize(kafo)
    super
    param = kafo.param('foreman', 'initial_organization')
    @organization = param.nil? ? 'Default Organization' : param.value

    param = kafo.param('foreman', 'initial_location')
    @location = param.nil? ? 'Default Location' : param.value

    @domain = kafo.param('foreman_proxy', 'dns_zone').value

    @netmask = kafo.param('foreman_plugin_fusor', 'netmask').value
    @network = kafo.param('foreman_plugin_fusor', 'network').value
    @ip = kafo.param('foreman_proxy', 'tftp_servername').value
    @from = kafo.param('foreman_plugin_fusor', 'from').value
    @to = kafo.param('foreman_plugin_fusor', 'to').value
    @gateway = kafo.param('foreman_proxy', 'dhcp_gateway').value

    @default_root_pass = kafo.param('foreman_plugin_fusor', 'root_password').instance_variable_get('@value')
    @default_ssh_public_key = kafo.param('foreman_plugin_fusor', 'ssh_public_key').value
    @ntp_host = kafo.param('foreman_plugin_fusor', 'ntp_host').value
    @timezone = kafo.param('foreman_plugin_fusor', 'timezone').value

    @kernel = "fdi-image-rhel_7-vmlinuz"
    @initrd = "fdi-image-rhel_7-img"
  end

  def seed
    say HighLine.color("Starting to seed provisioning data", :good)
    default_proxy = find_default_proxy
    default_organization = find_default_organization
    default_location = find_default_location
    foreman_host = find_foreman_host

    default_product = @foreman.products.katello_search_or_ensure({ 'organization_id' => default_organization['id']},
                                                                 { 'search' => 'name = Fusor' },
                                                                 { 'name' => 'Fusor' })

    puppet_repo = @foreman.repositories.katello_search_or_ensure({ 'organization_id' => default_organization['id'],
                                                                   'product_id' => default_product['id']},
                                                                 { 'search' => 'name = Puppet' },
                                                                 { 'name' => 'Puppet',
                                                                   'content_type' => 'puppet' })
    upload_puppet_modules(puppet_repo)

    default_content_view = @foreman.content_views.katello_search_or_ensure(
                                                                 { 'organization_id' => default_organization['id'],
                                                                   'nondefault' => true},
                                                                 { 'search' => 'name = "Fusor Puppet Content"' },
                                                                 { 'name' => 'Fusor Puppet Content' })

    @foreman.content_view_puppet_modules.katello_search_or_ensure(
                                                         { 'content_view_id' => default_content_view['id'] },
                                                         { 'search' => 'name = ovirt AND author = jcannon' },
                                                         { 'name' => 'ovirt', 'author' => 'jcannon' })

    publish_task = @foreman.api_resource(:content_views).
                            action(:publish).
                            call({ :id => default_content_view['id'] })

    default_domain = @foreman.domains.show_or_ensure({'id' => @domain},
                                                    {'name' => @domain,
                                                     'fullname' => 'Default domain used for provisioning',
                                                     'dns_id' => default_proxy['id']})

    default_subnet = @foreman.subnets.show_or_ensure({'id' => 'default'},
                                                    {'name' => 'default',
                                                     'mask' => @netmask,
                                                     'network' => @network,
                                                     'dns_primary' => @ip,
                                                     'from' => @from,
                                                     'to' => @to,
                                                     'gateway' => @gateway,
                                                     'domain_ids' => [default_domain['id']],
                                                     'dns_id' => default_proxy['id'],
                                                     'dhcp_id' => default_proxy['id'],
                                                     'tftp_id' => default_proxy['id'],
                                                     'boot_mode' => 'DHCP'})

    kinds = @foreman.template_kinds.index
    provisioning = kinds.detect { |k| k['name'] == 'provision' }
    pxe_linux = kinds.detect { |k| k['name'] == 'PXELinux' }
    default_config_templates = []

    rhev_self_hosted_ptable = @foreman.ptables.show_or_ensure(
                                            {'id' => 'ptable_rhev_self_hosted'},
                                            {
                                              'name' => 'rhev_self_hosted',
                                              'os_family' => 'Redhat',
                                              'layout' => ptable_rhev_self_hosted_snippet
                                            })

    name = 'PXELinux global default'
    pxe_template = @foreman.config_templates.show_or_ensure({'id' => name},
                                                            {'template' => template})
    default_config_templates << pxe_template

    @foreman.config_templates.build_pxe_default

    @media = []
    default_puppet_environment = @foreman.environments.show!({'id' => puppet_environment_name(default_organization,
                                                                                              default_content_view) })
    hostgroup_attrs = {'name' => "Fusor Base",
                       'domain_id' => default_domain['id'],
                       'subnet_id' => default_subnet['id']}
    default_hostgroup = @foreman.hostgroups.show_or_ensure({'id' => "Fusor Base"}, hostgroup_attrs)
    @foreman.parameters.show_or_ensure({'id' => 'ntp-server', 'hostgroup_id' => 'Fusor Base'},
                                         {
                                           'name' => 'ntp-server',
                                           'value' => @fqdn,
                                         })
    setup_idle_timeout
    setup_default_root_pass
    setup_ignore_puppet_facts_for_provisioning

    @foreman.environments.import_puppetclasses({ 'id' => default_proxy['id'], 'environment_id' => default_puppet_environment['id'] })

    assign_organization(default_organization,
                        { 'domain' => default_domain, 'subnet' => default_subnet,
                          'config_templates' => default_config_templates, 'hostgroups' => [default_hostgroup],
                          'environments' => [default_puppet_environment],
                          'media' => @media,
                          'ptables' => @foreman.ptables.index })
    assign_location(default_location,
                    { 'domain' => default_domain, 'subnet' => default_subnet,
                      'config_templates' => default_config_templates, 'hostgroups' => [default_hostgroup],
                      'environments' => [default_puppet_environment],
                      'media' => @media })
  end

  private

  def puppet_environment_name(organization, content_view)
    "KT_" + organization['label'] + "_Library_" + content_view['label'] + "_" + content_view['id'].to_s
  end

  def assign_organization(organization, objects)
    domain_ids = organization['domains'].map { |d| d['id'] }
    subnet_ids = organization['subnets'].map { |s| s['id'] }
    config_template_ids = organization['config_templates'].map { |t| t['id'] }
    hostgroup_ids = organization['hostgroups'].map { |h| h['id'] }
    environment_ids = organization['environments'].map { |e| e['id'] }
    medium_ids = organization['media'].map { |m| m['id'] }
    ptable_ids = organization['ptables'].map { |p| p['id'] }

    @foreman.organizations.update('id' => organization['id'],
                                  'organization' => { 'domain_ids' => (domain_ids + [objects['domain']['id']]).uniq,
                                                      'subnet_ids' => (subnet_ids + [objects['subnet']['id']]).uniq,
                                                      'config_template_ids' => (config_template_ids + objects['config_templates'].map{ |t| t['id'] }).uniq,
                                                      'hostgroup_ids' => (hostgroup_ids + objects['hostgroups'].map{ |h| h['id'] }).uniq,
                                                      'environment_ids' => (environment_ids + objects['environments'].map{ |e| e['id'] }).uniq,
                                                      'medium_ids' => (medium_ids + objects['media'].map{ |m| m['id'] }).uniq,
                                                      'ptable_ids' => (ptable_ids + objects['ptables'].map{ |p| p['id'] }).uniq })
  end

  def assign_location(location, objects)
    domain_ids = location['domains'].map { |d| d['id'] }
    subnet_ids = location['subnets'].map { |s| s['id'] }
    config_template_ids = location['config_templates'].map { |t| t['id'] }
    hostgroup_ids = location['hostgroups'].map { |h| h['id'] }
    environment_ids = location['environments'].map { |e| e['id'] }
    medium_ids = location['media'].map { |m| m['id'] }

    @foreman.locations.update('id' => location['id'],
                              'location' => { 'domain_ids' => (domain_ids + [objects['domain']['id']]).uniq,
                                              'subnet_ids' => (subnet_ids + [objects['subnet']['id']]).uniq,
                                              'config_template_ids' => (config_template_ids + objects['config_templates'].map{ |t| t['id'] }).uniq,
                                              'hostgroup_ids' => (hostgroup_ids + objects['hostgroups'].map{ |h| h['id'] }).uniq,
                                              'environment_ids' => (environment_ids + objects['environments'].map{ |e| e['id'] }).uniq,
                                              'medium_ids' => (medium_ids + objects['media'].map{ |m| m['id'] }).uniq })
  end

  def setup_idle_timeout
    @foreman.settings.show_or_ensure({'id' => 'idle_timeout'},
                                     {'value' => 180.to_s})
  rescue NoMethodError => e
    @logger.error "Setting with name 'idle_timeout' not found, you must run 'foreman-rake db:seed' " +
                      "and rerun installer to fix this issue."
  end

  def setup_ignore_puppet_facts_for_provisioning
    @foreman.settings.show_or_ensure({'id' => 'ignore_puppet_facts_for_provisioning'},
                                     {'value' => 'true'})
  rescue NoMethodError => e
    @logger.error "Setting with name 'ignore_puppet_facts_for_provisioning' not found, you must run 'foreman-rake db:seed' " +
                      "and rerun installer to fix this issue."

  end

  def setup_default_root_pass
    @foreman.settings.show_or_ensure({'id' => 'root_pass'},
                                     {'value' => @default_root_pass.to_s.crypt('$5$fm')})
  rescue NoMethodError => e
    @logger.error "Setting with name 'root_pass' not found, you must run 'foreman-rake db:seed' " +
                      "and rerun installer to fix this issue."
  end

  def find_default_organization
    @foreman.organizations.show! 'id' => @organization,
                                 :error_message => "organization #{@organization} not found"
  end

  def find_default_location
    @foreman.locations.show! 'id' => @location,
                                 :error_message => "location #{@location} not found"
  end

  def find_default_proxy
    @foreman.smart_proxies.show! 'id' => @fqdn,
                                 :error_message => "smart proxy #{@fqdn} haven't been registered yet, installer failure?"
  end

  def upload_puppet_modules(repository)
    path = "/usr/share/ovirt-puppet/pkg/jcannon-ovirt-1.0.0.tar.gz"

    response = @foreman.api_resource(:repositories).action(:upload_content).
      call({ :id => repository['id'], :content => [::File.new(path, 'rb')]},
           { :content_type => 'multipart/form-data', :multipart => true })
  end

  def template
    <<EOS
DEFAULT menu
PROMPT 0
MENU TITLE PXE Menu
TIMEOUT 200
TOTALTIMEOUT 6000
ONTIMEOUT discovery

LABEL discovery
MENU LABEL Foreman Discovery
KERNEL boot/#{@kernel}
APPEND initrd=boot/#{@initrd} rootflags=loop root=live:/fdi.iso rootfstype=auto ro rd.live.image acpi=force rd.luks=0 rd.md=0 rd.dm=0 rd.lvm=0 rd.bootif=0 rd.neednet=0 nomodeset proxy.url=#{@foreman_url} proxy.type=foreman
IPAPPEND 2
EOS
  end

  def ptable_rhev_self_hosted_snippet
    <<'EOS'
zerombr
clearpart --all --initlabel
part /boot --fstype ext3 --size=200 --asprimary
part swap --recommended
part pv.01 --size=1 --grow

volgroup VolGroup01 pv.01
logvol / --fstype ext4 --name=root --vgname=VolGroup01 --size=1 --grow

EOS
  end
end
