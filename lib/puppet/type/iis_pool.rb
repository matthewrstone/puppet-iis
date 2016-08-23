Puppet::Type.newtype(:iis_pool) do
  desc 'The iis_pool type creates and manages IIS application pools'

  newproperty(:ensure) do
    desc 'Whether a pool should be started.'

    newvalue(:stopped) do
      provider.stop
    end

    newvalue(:started) do
      provider.start
    end

    newvalue(:present) do
      provider.create
    end

    newvalue(:absent) do
      provider.destroy
    end

    aliasvalue(:false, :stopped)
    aliasvalue(:true, :started)
  end

  newparam(:name, namevar: true) do
    desc 'This is the name of the application pool'
    validate do |value|
      raise("#{name} is not a valid applcation pool name") unless value =~ %r{^[a-zA-Z0-9\-\_\.'\s]+$}
    end
  end

  newproperty(:enable_32_bit) do
    desc 'If 32-bit is enabled for the pool'
    newvalues(:false, :true)
    defaultto :false
  end

  newproperty(:runtime) do
    desc '.NET runtime version for the pool'
    validate do |value|
      raise("#{runtime} must be a float") unless value =~ %r{^v?\d+\.\d+$}
    end
    munge do |value|
      "v#{value.gsub(%r{^v}, '').to_f}"
    end
  end

  newproperty(:pipeline) do
    desc 'The pipeline mode for the application pool'
    newvalues(
      :integrated,:Integrated,
      :classic,:Classic
    )
  end

## NEW APP POOL SETTINGS
  newproperty(:autostart) do
    desc 'Set the autostart property.'
    newvalues(:false,:true)
    defaultto(:true)
  end

  newproperty(:start_mode) do
    desc 'The start mode for the app pool.'
    newvalues(
      :ondemand,:OnDemand,
      :alwaysrunning,:alwaysrunning
    )
    #validate do |value|
    #  raise("#{start_mode must be OnDemand or AlwaysRunning}") unless value =~ %r{^(OnDemand|AlwaysRunning)$}
    #end
  end

  newproperty(:rapid_fail_protection) do
    desc 'Set the rapid fail protection property.'
    newvalues(:false,:true)
    defaultto(:true)
  end

  newproperty(:identitytype) do
    desc 'Set the identity type'
    newvalues(
      :localsystem,:LocalSystem,
      :localservice,:LocalService,
      :networkservice,:NetworkService,
      :specificuser,:SpecificUser,
      :applicationpoolidentity,:applicationpoolidentity
    )
  end

  newproperty(:username) do
    desc 'set a username'
  end

  newproperty(:password) do
    desc 'set a password'
  end

  newproperty(:idle_timeout) do
    desc 'set the idle timeout'
  end

  newproperty(:idle_timeout_action) do
    # property does not exists in Win2008r2?
    desc 'set the default idle timeout action'
    newvalues(:suspend,:terminate)
  end

  newproperty(:max_processes) do
    desc 'set max processes'
  end

  newproperty(:max_queue_length) do
    desc 'set max queue length'
  end

  newproperty(:recycle_perodic_minutes) do
    desc 'the recyle time in minutes'
  end

  newproperty(:recycle_schedule) do
    desc 'the recycle schedule'
  end

  newproperty(:recycle_logging, :array_matching => :all) do
    desc 'enable recycle logging'
    newvalues(
      :time,:time,
      :requests,:Requests,
      :schedule,:Schedule,
      :memory,:Memory,
      :isapiunhealthy,:IsapiUnhealthy,
      :ondemand,:OnDemand,
      :configchange,:ConfigChange,
      :privatememory,:PrivateMemory
    )
  end
  
  def refresh
    if self[:ensure] == :present && (provider.enabled? || self[:ensure] == 'started')
      provider.restart
    else
      debug 'Skipping restart; pool is not running'
    end
  end
end
