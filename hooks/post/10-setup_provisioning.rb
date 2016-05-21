require 'facter'

DEVEL_ENV= app_value(:devel_env)
if DEVEL_ENV
  USER = param("katello_devel", "user").value
  DEPLOYMENT_DIR = param("katello_devel", "deployment_dir").value
  RVM_RUBY = param("katello_devel", "rvm_ruby").value
end

def rails_pid
  pid_file = File.join(DEPLOYMENT_DIR, "foreman", "tmp", "pids", "server.pid")

  if File.exists?(pid_file)
    File.open(pid_file) { |f| f.read }
  else
    nil
  end
end

def rails_running?
  return false unless (pid = rails_pid)
  Process.getpgid(pid.to_i)
rescue Errno::ESRCH
  false
end

def kill_server(pid = rails_pid)
  say "Killing rails server with pid: #{pid}"
  system("kill -9 #{pid}")
  say HighLine.color("Rails server stopped", :good)
end

def run_rails
  if rails_running?
    say HighLine.color("Rails server already running", :bad)
    return
  end

  system "sudo su #{USER} -c '/bin/bash --login -c \"rvm use #{RVM_RUBY} && cd #{DEPLOYMENT_DIR}/foreman && bundle exec rails s -d\"'"
  say HighLine.color("Rails server started", :good)
end

if app_value(:provisioning_wizard) != 'none' && [0,2].include?(kafo.exit_code)
  require File.join(KafoConfigure.root_dir, 'hooks', 'lib', 'foreman.rb')
  require File.join(KafoConfigure.root_dir, 'hooks', 'lib', 'base_seeder.rb')
  require File.join(KafoConfigure.root_dir, 'hooks', 'lib', 'provisioning_seeder.rb')

  say "Starting configuration..."
  if app_value(:devel_env)
    # TODO: devel_env doesn't run via apache, it uses a proxy pass and for some
    # reason we're having trouble registering the sat host via puppet
    system("echo ':restrict_registered_smart_proxies: false' >> #{DEPLOYMENT_DIR}/foreman/config/settings.yaml")

    run_rails
    say "Rails is running in PID: #{rails_pid}"
  end

  # we must enforce at least one puppet run
  logger.debug 'Running puppet agent to seed foreman data'
  fqdn =  Facter.value('fqdn')
  `su puppet --shell /bin/bash -c 'mkdir -p /var/lib/puppet/yaml/facts/'`
  `service puppet stop`
  `su puppet --shell /bin/bash -c 'puppet facts find #{fqdn} --render-as yaml > /var/lib/puppet/yaml/facts/#{fqdn}.yaml'`
  `puppet agent -t --no-pluginsync`
  `service puppet start`
  logger.debug 'Puppet agent run finished'

  # add other provisioning data
  pro_seeder = ProvisioningSeeder.new(kafo)
  pro_seeder.seed

  say HighLine.color("Setup provisioning step complete.", :good)
else
  say "Not running provisioning configuration since installation encountered errors, exit code was <%= color('#{kafo.exit_code}', :bad) %>"
  false
end

