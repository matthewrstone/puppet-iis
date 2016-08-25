Puppet::Type.newtype(:iis_binding) do
  desc 'crap on a cracker'
  
  ensurable

  newparam(:binding,:namevar => true) do
      validate do |value|
          unless value =~ /^(\*|(([0-9]){1,3}\.([0-9]){1,3}\.([0-9]){1,3}\.([0-9]){1,3})):\d*:.*$/
              raise 'Title/Binding must be in the format of "127.0.0.1:80:mywebsite.com". "*" are allowed.'
          end
      end
  end

  newparam(:ensure) do
  end

  newproperty(:site_name) do
  end

  newproperty(:protocol) do
      validate do |value|
          unless value =~ /http|https|net.pipe|netmsmq|msmq.formatname/
              raise 'protocol must be http,https,net.pipe,netmsmq or msmq.formatname'
          end
      end
  end

  newproperty(:port) do
      validate do |value|
          unless value.to_i
              raise 'port must be a number'
          end
      end
  end

  newproperty(:host_header) do
  end

  newproperty(:ip_address) do
      validate do |value|
          unless value =~ /^([0-9]){1,3}\.([0-9]){1,3}\.([0-9]){1,3}\.([0-9]){1,3}$/
              raise 'ip_address is not a valid ip address.'
          end
      end
  end

  newproperty(:store) do
  end

  newproperty(:sslflag) do
  end

  newproperty(:certificate_thumbprint) do
  end

end