class BaseWizard
  def self.attrs
    raise NotImplementedError
  end

  def self.order
    raise NotImplementedError
  end

  def self.custom_labels
    raise NotImplementedError
  end

  attr_accessor :header, :help, :allow_cancellation

  def initialize(kafo)
    @kafo   = kafo
    @logger = kafo.logger
    @hide_password = true
    # set default value according to parameter value
    self.class.attrs.each_pair do |attr, name|
      param = kafo_param(attr)
      value = param && param.value
      if param.is_a?(Kafo::Params::Password) # for password we need decrypted but hidden value
        param.value = param.default if param.value.nil?
        param.send(:decrypt) if param.send(:encrypted?)
        value = send(attr) || param.instance_variable_get('@value')
      end
      send "#{attr}=", value
    end
  end

  def start
    configure = @kafo.config.app[:provisioning_wizard] != 'non-interactive'
    while configure
      send("get_#{configure}") if configure.is_a?(Symbol)
      configure = get_ready
      configure = true if !configure && !validate
    end
  end

  def method_missing(name, *args, &block)
    if name.to_s =~ /^get_(.*)/ && self.class.attrs.keys.include?(attr = $1.to_sym)
      send "#{$1}=", ask("new value for #{self.class.attrs[attr]}")
    else
      super
    end
  end

  def respond_to?(name)
    if name.to_s =~ /^get_(.*)/ && self.class.attrs.keys.include?($1.to_sym)
      true
    else
      super
    end
  end

  private

  def validate
    errors = self.class.order.map do |attr|
      method_name = "validate_#{attr}"
      send(method_name) if respond_to?(method_name)
    end.compact

    say HighLine.color("\nUnable to proceed because of following errors:", :bad) unless errors.empty?
    errors.each { |error| say '  ' + HighLine.color(error, :bad) }
    errors.empty?
  end

  def kafo_param(attr)
    @kafo.param('fusor', attr.to_s)
  end

  def print_configuration
    say HighLine.color(header, :headline) unless header.nil?
    self.class.order.each do |attr|
      name = self.class.attrs[attr.to_sym]
      value = kafo_param(attr).is_a?(Kafo::Params::Password) && @hide_password ? '*' * send(attr).size : send(attr)
      print_pair name, value
    end
  end

  def print_pair(name, value)
    value = case
              when value.is_a?(TrueClass)
                HighLine.color(Kafo::Wizard::OK, :run)
              when value.is_a?(FalseClass)
                HighLine.color(Kafo::Wizard::NO, :cancel)
              else
                "'#{HighLine.color(value.to_s, :info)}'"
            end

    say "#{name}:".rjust(25) + " #{value}"
  end

  def get_ready
    choose do |menu|
      say "\n#{self.help}"
      menu.header = "\nModify settings as needed, and then proceed with the installation"
      menu.prompt = ''
      menu.select_by = :index
      adjustment  = 26
      count = 1
      menu.choice(HighLine.color("Proceed with the values shown".rjust(adjustment+8), :run)) { false }
      self.class.order.each do |attr|
        count += 1
        name = self.class.attrs[attr.to_sym]
        value = kafo_param(attr).is_a?(Kafo::Params::Password) && @hide_password ? '*' * send(attr).size : send(attr)
        name_label  = "#{name}"
        value_label = " | #{value}" 
        if (count < 10) && (menu.index.eql? :number)
          label = self.class.custom_labels[attr.to_sym] || name_label.rjust(adjustment+1) + value_label 
        else
          label = self.class.custom_labels[attr.to_sym] || name_label.rjust(adjustment) + value_label
        end
        label = "Do not " + label.downcase if send(attr).is_a?(TrueClass) && attr != "register_host"
        label = label
        menu.choice(label) { attr.to_sym }
      end
      menu.choice(HighLine.color('Cancel installation', :cancel)) { @kafo.class.exit(100) } if self.allow_cancellation
    end
  rescue Interrupt
    @logger.debug "Got interrupt, exiting"
    @kafo.class.exit(100)
  end

end
