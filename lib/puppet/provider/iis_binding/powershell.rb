require 'puppet/provider/iispowershell'
require 'csv'
Puppet::Type.type(:iis_binding).provide(:powershell, parent: Puppet::Provider::Iispowershell) do
  mk_resource_methods
  def self.instances
      b_array = []
      win2008 = Facter.value(:kernelmajversion) == '6.1'
      if win2008
          result = run("Import-Module WebAdministration; Get-WebBinding | ConvertTo-Csv -NoTypeInformation")
      else
          result = run("Get-WebBinding | ConvertTo-Csv -NoTypeInformation")
      end
      csv = CSV.parse(result,:headers => true)
      csv.each do |item|
          site_name = item['ItemXPath'].match(%r{@name='([a-z0-9_\ ]+)'}i)[1]
          binding_info = item['bindingInformation']
          name = "#{site_name} (#{binding_info})"

          host_header = item['bindingInformation'].split(':')[2]
          if !host_header
              host_header = "*"
          end
          binding = {
              :ensure      => :present,
              :name        => binding_info,
              :site_name   => site_name,
              :ip_address  => item['bindingInformation'].split(':')[0],
              :host_header => host_header,
              :port        => item['bindingInformation'].split(':')[1],
              :protocol    => item['protocol'],
              :cert_store  => item['certificateStoreName'],
              :cert_hash   => item['certificateHash'],
              :ssl_flag    => item['sslFlag'],
              :binding     => binding_info,
          }
          b_array.push(binding)
      end
      b_array.map {|b| new(b)}
  end

  def self.prefetch(resources)
      bnd = instances
      resources.keys.each do |bd|
        if provider = bnd.find { |b| b.name == bd }
          resources[bd].provider = provider
        end
      end
  end

  def exists?
      @property_hash[:ensure] == :present
  end

  def create
      win2008 = Facter.value(:kernelmajversion) == '6.1'
      if !@resource[:port] then @resource[:port] = @resource[:binding].split(':')[1] end
      if !@resource[:host_header] then @resource[:host_header] = @resource[:binding].split(':')[2] end
      if !@resource[:ip_address] then @resource[:ip_address] = @resource[:binding].split(':')[0] end
      if !@resource[:host_header] then @resource[:host_header] = '*' end
      create_switches = [
          "-Name #{@resource[:site_name]}",
          "-Port #{@resource[:port]}",
          "-Protocol #{@resource[:protocol]}",
          "-HostHeader #{@resource[:host_header]}",
          "-IPAddress #{@resource[:ip_address]}",
      ]
      if win2008 == false and protocol == 'https'
          create_switches << "-SslFlags $true"
      elsif win2008 == false and @resource['ssl_flag']
          create_switches << "-SslFlags #{@resource['ssl_flag']}"
      end
      cmd = "Import-Module WebAdministration; New-WebBinding #{create_switches.join(' ')}"
      result = Puppet::Type::Iis_binding::ProviderPowershell.run(cmd)
      Puppet.debug "Response from PowerShell create task: #{result}"
  end

  def destroy
      cmd = "Import-Module WebAdministration; Remove-WebBinding -BindingInformation #{resource[:binding]}"
      result = Puppet::Type::Iis_binding::ProviderPowershell.run(cmd)
      Puppet.debug "Response from PowerShell destroy task: #{result}"
  end

end