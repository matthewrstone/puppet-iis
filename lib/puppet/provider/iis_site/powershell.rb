require 'puppet/provider/iispowershell'
require 'rexml/document'
include REXML

Puppet::Type.type(:iis_site).provide(:powershell, parent: Puppet::Provider::Iispowershell) do
  def initialize(value = {})
    super(value)
    @property_flush = {
      'itemproperty' => {},
      'binders'      => {}
    }
  end

  def self.iisnames
    {
      name: 'name',
      path: 'physicalPath',
      app_pool: 'applicationPool'
    }
  end

  def self.webconfig
    {
      id: 'id',
    }
  end

  def self.instances
    sites = []
    inst_cmd = <<-ps1
Import-Module WebAdministration;
gci "IIS:\\sites" | %{ Get-ItemProperty $_.PSPath  | Select name, id, PhysicalPath, ApplicationPool, HostHeader, State, Bindings } | ConvertTo-Xml -Depth 4 -As String -NoTypeInformation
ps1
    result = run(inst_cmd)
    xml = Document.new result
    xml.root.each_element do |object|
      host_header = object.elements["Property[@Name='bindings']/Property[@Name='Collection']/Property/Property[@Name='bindingInformation']"].text.split(':')[2]
      if !host_header
        host_header = "*"
      end

      site_hash = {
          :state        => object.elements["Property[@Name='state']"].text.downcase,
          :name         => object.elements["Property[@Name='name']"].text,
          :id           => object.elements["Property[@Name='id']"].text,
          :protocol     => object.elements["Property[@Name='bindings']/Property[@Name='Collection']/Property/Property[@Name='protocol']"].text,
          :ip           => object.elements["Property[@Name='bindings']/Property[@Name='Collection']/Property/Property[@Name='bindingInformation']"].text.split(':')[0],
          :port         => object.elements["Property[@Name='bindings']/Property[@Name='Collection']/Property/Property[@Name='bindingInformation']"].text.split(':')[1],
          :host_header  => host_header,
          :app_pool     => object.elements["Property[@Name='applicationPool']"].text,
          :path         => object.elements["Property[@Name='physicalPath']"].text,
      }
      unless Facter.value(:kernelmajversion) == '6.1'
        ssl_flags = if object.elements["Property[@Name='bindings']/Property[@Name='Collection']/Property/Property[@Name='sslFlags']"].text === 0
          :false
        else
          :true
        end
        site_hash[:ssl] = ssl_flags
      end
      sites.push(site_hash)
    end
    sites.map do |site|
      if !@property_hash[:ssl] then @resource[:ssl] = :false end
      case Facter.value(:kernelmajversion)
        when %r{6.1}
          new(
              :ensure      => site[:state],
              :name        => site[:name],
              :port        => site[:port],
              :id          => site[:id],
              :protocol    => site[:protocol],
              :ip          => site[:ip],
              :host_header => site[:host_header],
              :app_pool    => site[:app_pool],
              :path        => site[:path],
          )
        else
          new(
              :ensure      => site[:state],
              :name        => site[:name],
              :port        => site[:port],
              :id          => site[:id],
              :protocol    => site[:protocol],
              :ip          => site[:ip],
              :host_header => site[:host_header],
              :app_pool    => site[:app_pool],
              :path        => site[:path],
              :ssl         => site[:ssl],
          )
      end
    end
  end

  def self.prefetch(resources)
    sites = instances
    resources.keys.each do |site|
      # rubocop:disable Lint/AssignmentInCondition
      if provider = sites.find { |s| s.name == site }
        resources[site].provider = provider
      end
    end
  end

  def exists?
    Puppet.notice "exists"
    %w(stopped started).include?(@property_hash[:ensure])
  end

  mk_resource_methods

  def create
    Puppet.notice "create"
    create_switches = [
      "-Name \"#{@resource[:name]}\"",
      "-Port #{@resource[:port]} -IP #{@resource[:ip]}",
      "-HostHeader \"#{@resource[:host_header]}\"",
      "-PhysicalPath \"#{@resource[:path]}\"",
      "-ApplicationPool \"#{@resource[:app_pool]}\"",
      '-Force'
    ]
    unless Facter.value(:kernelmajversion) == '6.1' then create_switches << "-Ssl:$#{@resource[:ssl]}" end
    inst_cmd = "Import-Module WebAdministration; New-Website #{create_switches.join(' ')}"
    resp = Puppet::Type::Iis_site::ProviderPowershell.run(inst_cmd)
    Puppet.debug "Creation powershell response was #{resp}"

    @resource.original_parameters.each_key do |k|
      @property_hash[k] = @resource[k]
    end
    @property_hash[:ensure]      = :present unless @property_hash[:ensure]
    @property_hash[:port]        = @resource[:port]
    @property_hash[:ip]          = @resource[:ip]
    @property_hash[:host_header] = @resource[:host_header]
    @property_hash[:path]        = @resource[:path]
    if Facter.value(:kernelmajversion) == '6.1'
      if !@resource[:ssl]
        @property_hash[:ssl] = :false
      else
        @property_hash[:ssl] = @resource[:ssl]
      end
    end
    exists? ? (return true) : (return false)
  end

  def destroy
    inst_cmd = "Import-Module WebAdministration; Remove-Website -Name \"#{@property_hash[:name]}\""
    resp = Puppet::Type::Iis_site::ProviderPowershell.run(inst_cmd)
    raise(resp) unless resp.empty?
    @property_hash.clear
    exists? ? (return false) : (return true)
  end

  webconfig.each do |property,item|
    define_method "#{property}=" do |value|
      @property_flush['webconfig'][item] = value
      @property_hash[property.to_sym] = value
    end
  end

  iisnames.each do |property, iisname|
    next if property == :ensure
    next if property == :ssl and Facter.value(:kernelmajversion) == '6.1'
    define_method "#{property}=" do |value|
      @property_flush['itemproperty'][iisname] = value
      @property_hash[property.to_sym] = value
    end
  end

  # These three properties have to be submitted together
  def self.binders
    %w(
      protocol
      ip
      port
      host_header
      ssl
    )
  end

  binders.each do |property|
    define_method "#{property}=" do |value|
      @property_flush['binders'][property] = value
      @property_hash[property.to_sym] = value
    end
  end

  def start
    create unless exists?
    @property_hash[:name]    = @resource[:name]
    @property_flush['state'] = :Started
    @property_hash[:ensure]  = 'started'
  end

  def stop
    create unless exists?
    @property_hash[:name]    = @resource[:name]
    @property_flush['state'] = :Stopped
    @property_hash[:ensure]  = 'stopped'
  end

  def restart
    inst_cmd = [
      'Import-Module WebAdministration',
      "Stop-WebSite -Name \"#{@resource[:name]}\"",
      "Start-WebSite -Name \"#{@resource[:name]}\""
    ]
    resp = Puppet::Type::Iis_site::ProviderPowershell.run(inst_cmd.join('; '))
    raise(resp) unless resp.empty?
  end

  def enabled?
    inst_cmd = "Import-Module WebAdministration; (Get-WebSiteState -Name \"#{@resource[:name]}\").value"
    resp = Puppet::Type::Iis_site::ProviderPowershell.run(inst_cmd).rstrip
    case resp
    when 'Started'
      true
    else
      false
    end
  end

  def flush
    command_array = []
    command_array << 'Import-Module WebAdministration; '
    if @property_flush['state']
      state_cmd = if @property_flush['state'] == :Started
                    'Start-Website'
                  else
                    'Stop-Website'
                  end
      state_cmd += " -Name \"#{@property_hash[:name]}\""
      command_array << state_cmd
    end
    # This will iterate over any 'Set-WebConfigurationProperty' items, currently only the site id.
    unless Facter.value(:kernelmajversion) == '6.1'
      @property_flush['webconfig'].each do |webconfig, value|
        Puppet.notice webconfig
        command_array << "Set-WebConfigurationProperty '/system.applicationhost/sites/site[@name=\"#{@property_hash[:name]}\"]' -name \"#{webconfig}\" -Value \"#{value}\""
      end
    end
    # This will iterate over any 'Set-ItemProperty' items.
    @property_flush['itemproperty'].each do |iisname, value|
      command_array << "Set-ItemProperty -Path \"IIS:\\\\Sites\\#{@property_hash[:name]}\" -Name \"#{iisname}\" -Value \"#{value}\""
    end
    bhash = {}
    unless @property_flush['binders'].empty?
      Puppet::Type::Iis_site::ProviderPowershell.binders.each do |b|
        if @property_flush['binders'].key?(b)
          bhash[b] = @property_flush['binders'][b] unless @property_flush['binders'][b] == 'false'
        else
          bhash[b] = @property_hash[b.to_sym]
        end
      end
      binder_cmd = "Set-ItemProperty -Path \"IIS:\\\\Sites\\#{@property_hash[:name]}\" -Name Bindings -Value @{protocol=\"#{bhash['protocol']}\";bindingInformation=\"#{bhash['ip']}:#{bhash['port']}:#{bhash['host_header']}"
      binder_cmd += '"'
      # Append sslFlags to args is enabled
      binder_cmd += '; sslFlags=0' if bhash['ssl'] && bhash['ssl'] != :false
      binder_cmd += '}'
      command_array << binder_cmd
    end
    resp = Puppet::Type::Iis_site::ProviderPowershell.run(command_array.join('; '))
    raise(resp) unless resp.empty?
  end
end