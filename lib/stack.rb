#!/usr/bin/env ruby
# Copyright 2012 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
# Author: Simon McCartney <simon.mccartney@hp.com>
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
require 'bundler'
require 'rubygems'

require 'base64'
require 'erb'
require 'openstack'     # https://github.com/ruby-openstack/ruby-openstack
require 'json'          # http://www.ruby-doc.org/stdlib-1.9.3/libdoc/json/rdoc/JSON.html
require 'tempfile'


#
# This really needs to be converted into a class....
#
module Stack

  # Shadow the global constant Logger with Stack::Logger
  # (if you want access to the global constant, use ::Logger from inside the Stack module)
  Logger = Logger.new(STDOUT)
  Logger.level = ::Logger::INFO
  Logger.datetime_format = "%Y-%m-%d %H:%M:%S"
  Logger.formatter = proc do |severity, datetime, progname, msg|
      "#{datetime} #{severity}: #{msg}\n"
  end

  # location of gem, where config[:gemhome]/lib contains our default cloud-init templates
  @@gemhome = File.absolute_path(File.realpath(File.dirname(File.expand_path(__FILE__)) + '/..'))

  # Methadone::CLILogger is a Class, Stack is still a module, so we can't include it
  # so this is a QADH to propagate the log_level
  def Stack.log_level(level)
    Logger.debug { "Setting the Logger.level to #{level}" }
    Logger.level = level
  end

  def Stack.show_stacks(stackfile = 'Stackfile')
    # our local config file
    config_raw = File.read(stackfile)
    eval(config_raw)

    Logger.info { "Stacks:" }
    StackConfig::Stacks.each do |name, details|
      Logger.info { "  #{name}" }
    end
  end

  def Stack.show_stack(config)
    # syntax_check is a light weight check that doesn't talk to OpenStalk
    Stack.syntax_check(config)
    # generate an array of hostnames that this stack would create
    hostnames = Stack.generate_server_names(config)

    hostnames.each { |hostname| Logger.info "  #{hostname}" }
  end

  def Stack.select_stack(stackfile = 'Stackfile', stack_name)
    # our local config file
    config_raw = File.read(stackfile)
    eval(config_raw)

    # if there is only one stack defined in the Stackfile, load it:
    if StackConfig::Stacks.count == 1 && stack_name.nil?
      stack_name = StackConfig::Stacks.keys[0]
      Logger.info { "Defaulting to #{stack_name} as there is a single stack defined and no stack named" }
    end

    # returns a config object, injecting the name into the returned config
    if StackConfig::Stacks[stack_name].nil?
      Logger.error { "#{stack_name} is invalid, defined stacks are:" }
      StackConfig::Stacks.each do |name, details|
        Logger.error { "  #{name}" }
      end
      exit 2
    end

    config = StackConfig::Stacks[stack_name]
    config[:name] = stack_name
    # set the stackhome to the directory containing the Stackfile
    config[:stackhome] = File.dirname(File.expand_path(stackfile))
    Logger.info "stackhome is #{config[:stackhome]}"

    config
  end

  def Stack.connect(config, region = nil)
    # region & az concepts are confused in HPCS land
    region = config['REGION'] if (region.nil? || region.length() < 1)

    Logger.debug "Connecting to OpenStack with region = #{region}"

    OpenStack::Connection.create({
                                  :auth_method=> 'password',
                                  :username => config['USERNAME'],
                                  :api_key=> config['PASSWORD'],
                                  :auth_url => config['AUTH_URL'],
                                  :authtenant_name => config['TENANT_NAME'],
                                  :region => region,
                                  :service_type=>"compute"
                                  })
  end

  # expects server to be OpenStack::Compute::Server object
  def Stack.get_addresses(server)

    # get the addressess associated with an OpenStack::Compute::Server object
    address_description = String.new
    server.addresses.each do |address|
      address_description << "#{address.address}(#{address.label}) "
    end
    address_description
  end

  # check that all the required config items are set
  def Stack.syntax_check(config)
    if config['REGION'].nil? || config['USERNAME'].nil? || config['PASSWORD'].nil? || config['AUTH_URL'].nil? || config['TENANT_NAME'].nil? &&
       config['REGION'].empty? || config['USERNAME'].empty? || config['PASSWORD'].empty? || config['AUTH_URL'].empty? || config['TENANT_NAME'].empty?
      Logger.error { "REGION, USERNAME, PASSWORD, AUTH_URL & TENANT_NAME must all be set" }
      exit
    end

    # load defaults for any items not configured
    Stack.populate_config(config)

    if config[:provisioner] == 'chef'
      # check that we have semi-sensible Chef setup
      # at a bare minimum, we need the directory where we're going to download
      # validation.pem to to exist
      dot_chef_abs = File.absolute_path(config[:stackhome] + '/' + config[:dot_chef])
      if !File.directory?(dot_chef_abs)
        Logger.warn "#{dot_chef_abs} doesn't exist"
      end

      # Check we have a #{dot_chef_abs}/.chef/knife.rb
      knife_rb_abs = dot_chef_abs + '/knife.rb'
      if File.exists?(knife_rb_abs)
        Logger.info "Found #{knife_rb_abs}, lets hope it contains something sensible"
      else
        Logger.warn "#{knife_rb_abs} doesn't exist, please run 'stack-kicker configure-knife <stack-name>'"
      end
    end
  end

  # validate that all our OpenStack creds, image_id, flavors, keys etc are valid
  def Stack.validate(config)

    Stack.syntax_check(config)

    # check that the ssh-key is loaded, otherwise most post-install scripts will fail
    # this lazily assumes that the :key_pair name matches the file the keys were loaded
    # from
    if (0 == 1)
      ssh_keys_loaded = `ssh-add -L`
      Logger.debug "ssh_keys_loaded: #{ssh_keys_loaded}"
      Logger.debug "Looking for #{config[:key_pair]}"
      if ssh_keys_loaded.include?(config[:key_pair])
        Logger.info "Found #{config[:key_pair]} in the ssh-agent key list"
      else
        Logger.error "Couldn't find #{config[:key_pair]} key in the ssh-agent key list! Aborting!"
        Logger.erroLogger.error "ssh_keys_loaded: #{ssh_keys_loaded}"
        exit 2
      end
    end

    # populate the config & then walk through the AZs verifying the config
    Stack.populate_config(config)

    # Check that we have valid details for each AZ
    config[:azs].each do |az|

      # check that credentials, flavor & image are valid
      os = connect(config, az)

      Logger.info "Checking that flavor #{config['flavor_id']} exists in #{az}..."
      flavor = os.get_flavor(config['flavor_id'])
      Logger.info "#{config['flavor_id']} is #{flavor.name}"

      Logger.info "Checking that image #{config[az]['image_id']} exists in #{az}..."
      image = os.get_image(config[az]['image_id'])
      Logger.info "#{config[az]['image_id']} is #{image.name}"

      Logger.info "Checking that keypair #{config[:key_pair]} exists in #{az}...."
      keypairs = os.keypairs()
      if (keypairs[config[:key_pair]].nil? && keypairs[config[:key_pair].to_sym].nil?)
        Logger.warn "#{config[:key_pair]} isn't available, uploading the key"

        # upload the key
        key =  os.create_keypair({:name=> config[:key_pair], :public_key=> File.read(config[:key_public])})
        Logger.warn "#{config[:key_pair]} fingerprint=#{key[:fingerprint]}"
      else
        Logger.info "#{config[:key_pair]} fingerprint=#{keypairs[config[:key_pair].to_sym][:fingerprint]}"
      end

      # TODO: check that security group exists
      # we should have a security group that matches each role
      # get all the secgroups
      security_groups = os.security_groups()
      # extract the names
      sg_names = security_groups.map { |secgroup, secgroup_details| secgroup_details[:name] }

      config[:roles].each do |role, role_details|
        # is does the secgroup exist?
        if sg_names.include?(role_details[:security_group])
          Logger.info "security group #{role_details[:security_group]} exists in #{az}"
        else
          Logger.error "security group #{role_details[:security_group]} is missing in #{az}"
        end
      end
    end
  end

  def Stack.generate_knife_rb(config)
    # generate a project/.chef/knife.rb from our config
    # (assumes the chef server is running for public IP access etc)

    # find the chef server, if we need to
    if config[:chef_server_hostname].nil? || config[:chef_server_private].nil? || config[:chef_server_public]
      Logger.debug { "Attempting to discover the chef server details" }
      ours = Stack.get_our_instances(config)
      ours.each do |node, node_details|
        if node_details[:role] == :chef
          Logger.debug { "Found the Chef server: #{node} #{node_details}" }
          Stack.set_chef_server(config, node)
        end
      end
    end

    # CWD shoud be chef-repo/bootstrap, so the project .chef directory should be
    dot_chef_abs = File.absolute_path(config[:stackhome] + '/' + config[:dot_chef])

    if !File.directory?(dot_chef_abs)
      Logger.warn "#{dot_chef_abs} doesn't exist, creating it..."
      Dir.mkdir(dot_chef_abs)
    end

    client_key = dot_chef_abs + '/' + config[:name] + '-' + ENV['USER'] + '.pem'
    validation_key = dot_chef_abs + '/' + config[:name] + '-' + 'validation.pem'

    Logger.debug "stackhome: #{config[:stackhome]}"
    Logger.debug "Current user client key: #{client_key}"
    Logger.debug "New Host Validation key: #{validation_key}"

    knife_rb_template = %q{
log_level                :info
log_location             STDOUT
node_name                '<%=ENV['USER']%>'
client_key               '<%=dot_chef_abs%>/'+ ENV['USER'] + '.pem'
validation_client_name   'chef-validator'
validation_key           '<%=dot_chef_abs%>/validation.pem'
chef_server_url          '<%=config[:chef_server_public]%>'
cache_type               'BasicFile'
cache_options( :path =>  '<%=dot_chef_abs%>/checksums' )
cookbook_path [ '<%=config[:stackhome]%>/cookbooks' ]
    }

    knife_rb_erb = ERB.new(knife_rb_template)
    knife_rb = knife_rb_erb.result(binding)

    krb = File.new(dot_chef_abs + '/knife.rb', "w")
    krb.truncate(0)
    krb.puts knife_rb
    krb.close
  end

  # position is really the node number in a role, i.e. 1..count
  def Stack.generate_hostname(config, role, position)
    role_details = config[:roles][role]

    # TODO: don't calculate this everytime, shift out to a hash lookup
    Logger.debug config
    Logger.debug config[:site_template]
    Logger.debug role_details
    Logger.debug role_details[:azs]

    site = sprintf(config[:site_template], role_details[:azs][position-1].split('.')[0].sub(/-/, ''))

    # generate the hostname
    hostname = sprintf(config[:name_template], config[:global_service_name], site, role, position)

    hostname
  end

  def Stack.generate_server_names(config)
    Stack.populate_config(config)
    config[:hostnames] = config[:node_details].keys
    config[:hostnames]
  end

  def Stack.populate_config(config)
    # config[:role_details] contains built out role details with defaults filled in from stack defaults
    # config[:node_details] contains node details built out from role_details

    # set some sensible defaults to the stack-wide defaults if they haven't been set in the Stackfile.
    if config[:provisioner].nil?
      Logger.warn { "Defaulting to chef for config[:provisioner] "}
      config[:provisioner] = 'chef'
    end

    if config[:dot_chef].nil?
      Logger.warn { "Defaulting to .chef for config[:dot_chef] "}
      config[:dot_chef] = '.chef'
    end

    if config[:chef_environment].nil?
      Logger.warn { "Defaulting to _default for config[:chef_environment]" }
      config[:chef_environment] = '_default'
    end

    if config[:chef_validation_pem].nil?
      Logger.warn { "Defaulting to .chef/validation.pem for config[:chef_validation_pem]" }
      config[:chef_validation_pem] = '.chef/validation.pem'
    end

    if config[:name_template].nil?
      Logger.warn { "Defaulting to '%s-%s-%s%04d' for config[:name_template]" }
      config[:name_template] = '%s-%s-%s%04d'
    end

    if config[:site_template].nil?
      Logger.warn { "Defaulting to '%s' for config[:site_template]" }
      config[:site_template] = '%s'
    end

    if config[:global_service_name].nil?
      Logger.error { "Defaulting to 'UNKNOWN' for config[:global_service_name]" }
      config[:site_template] = 'UNKNOWN'
    end


    if config[:node_details].nil?
      Logger.debug { "Initializing config[:node_details] and config[:azs]" }
      config[:node_details] = Hash.new
      config[:azs] = Array.new

      config[:roles].each do |role,role_details|
        Logger.debug { "Setting defaults for #{role}" }

        # default to 1 node of this role if :count isn't set
        if role_details[:count].nil?
          role_details[:count] = 1
        end

        if (role_details[:data_dir].nil?)
          role_details[:data_dir] = '/dummy'
        end

        # Has the cloud_config_yaml been overridden?
        if (role_details[:cloud_config_yaml])
          role_details[:cloud_config_yaml] = Stack.find_file(config, role_details[:cloud_config_yaml])
        else
          role_details[:cloud_config_yaml] = Stack.find_file(config, 'cloud-config.yaml')
        end

        # Has the default bootstrap script been overridden
        if (role_details[:bootstrap])
          if (role_details[:bootstrap].empty?)
            Logger.debug { "role_details[:bootstrap] is empty, ignoring" }
          else
            role_details[:bootstrap] = Stack.find_file(config, role_details[:bootstrap])
          end
        else
          role_details[:bootstrap] = Stack.find_file(config, 'chef-client-bootstrap-excl-validation-pem.sh')
        end

        # we default to the role name for the security group unless explicitly set
        if role_details[:security_group].nil?
          role_details[:security_group] = role.to_s
        end

        # default to execing post install scripts in stackhome is a cwd wasn't set
        # (cwd is calculated relative to stackhome)
        if role_details[:post_install_cwd].nil?
          role_details[:post_install_cwd] = '/.'
        end

        if role_details[:post_install_args].nil?
          role_details[:post_install_args] = ''
        end

        (1..role_details[:count]).each do |p|
          Logger.debug { "Populating the config[:role_details][:azs] array with AZ" }
          role_details[:azs] = Array.new if role_details[:azs].nil?

          # is there an az set for this node?
          if role_details[:azs][p-1].nil?
            # inherit the global az
            Logger.debug { "Inheriting the AZ for #{role} (#{config['REGION']})" }
            role_details[:azs][p-1] = config['REGION']
          end

          # add this AZ to the AZ list, we'll dedupe later
          config[:azs] << role_details[:azs][p-1]

          hostname =  Stack.generate_hostname(config, role, p)
          Logger.debug { "Setting node_details for #{hostname}, using element #{p}-1 from #{role_details[:azs]}" }
          config[:node_details][hostname] = { :az => role_details[:azs][p-1], :region => role_details[:azs][p-1], :role => role }
        end
      end
    end
    config[:azs].uniq!

    # if set the region specific settings from the global settings if not already specified
    config[:azs].each do |az|
      # we store region spefic stuff in hash
      config[az] = Hash.new if config[az].nil?

      config[az]['image_id'] = config['image_id'] if config[az]['image_id'].nil?
    end

    config[:node_details]
  end

  # get all instances running in the current config
  # return a hash where key is the instance name, value is another hash containing :region, :id, :addresses
  def Stack.get_all_instances(config, refresh = false)
    if config[:all_instances].nil? || refresh
      # we need to get the server list for each AZ mentioned in the config[:roles][:role][:azs], this is populated by Stack.populate_config
      Stack.populate_config(config)

      # get the current list of servers from OpenStack & generate a hash, keyed on name
      servers = Hash.new
      config[:azs].each do |az|
        os = Stack.connect(config, az)
        os.servers.each do |server|
          servers[server[:name]] = {
            :region => az,
            :id => server[:id],
            :addresses => os.server(server[:id]).addresses
          }
        end
      end
      config[:all_instances] = servers
    end
    Stack.categorise_instance_ips(config)
    config[:all_instances]
  end

  # Add an instance to the :all_instances hash, instead of having to poll the whole lot again
  def Stack.add_instance(config, hostname, region, id, addresses)
    config[:all_instances][hostname] = { :region => region, :id => id, :addresses => addresses}
    Stack.categorise_instance_ips(config)
  end

  def Stack.categorise_instance_ips(config)
    Logger.debug { ">>> Stack.categorise_instance_ips" }
    # create a private_ip & public_ip array on the server objects for easy retrieval
    config[:all_instances].each do |hostname, instance_details|
      Logger.debug { "Flushing categorised addresses for #{hostname}" }
      config[:all_instances][hostname][:private_ips] = Array.new
      config[:all_instances][hostname][:public_ips] = Array.new

      Logger.debug { "Categorising addresses for #{hostname}" }
      config[:all_instances][hostname][:addresses].each do |address|
        case address.label
        when 'public'
          config[:all_instances][hostname][:public_ips] << address.address
        when 'private'
          config[:all_instances][hostname][:private_ips] << address.address
        else
          Logger.error "#{address.label} is an unhandled address type for #{hostname}"
        end
      end
    end
    Logger.debug { "config[:all_instances][= #{config[:all_instances]}" }
    Logger.debug { "<<< Stack.categorise_instance_ips" }
  end

  def Stack.get_public_ip(config, hostname)
    Logger.debug { "Stack.get_public_ip getting public IP for #{hostname}" }
    # get a public address from the instance
    # (could be either the dynamic or one of our floating IPs
    config[:all_instances][hostname][:addresses].each do |address|
      if address.label == 'public'
        Logger.debug { "public IP for #{hostname} is #{address.address}" }
        return address.address
      end
    end
  end

  def Stack.get_private_ip(config, hostname)
    # get the private address for an instance
    config[:all_instances][hostname][:addresses].each do |address|
      if address.label == 'private'
        return address.address
      end
    end
  end



  def Stack.show_running(config)
    # TODO: optionally show the hosts that are missing
    ours = Stack.get_our_instances(config)

    ours.each do |node, node_details|
      printf("%-30s %20s %8d %16s %s\n", node, node_details[:region], node_details[:id], node_details[:role], node_details[:addresses].map { |address| address.address })
    end
  end

  def Stack.ssh(config, hostname = nil, user = ENV['USER'], command = nil)
    # ssh to a host, or all hosts

    # get all running instances
    servers = Stack.get_our_instances(config)

    if hostname.nil?
      Logger.debug { "request to SSH to all hosts" }
      servers.each do |host, details|
        public_ip = Stack.get_public_ip(config, host)
        Logger.info { "#{host} #{public_ip}" }
        cmd_output =  `ssh -oStrictHostKeyChecking=no -l #{user} #{public_ip} "#{command}"`
        Logger.info { "#{host} #{public_ip} #{cmd_output}" }
      end
    else
      Logger.debug { "request to SSH to #{servers[hostname]}" }
    end
  end


  def Stack.get_our_instances(config)
    Logger.debug { ">>> Stack.get_our_instances" }
    # build an hash of running instances that match our generated hostnames
    node_details = Stack.populate_config(config)

    # get all of our hostnames
    hostnames = Stack.generate_server_names(config)

    # get all running instances
    servers = Stack.get_all_instances(config)

    running = Hash.new
    # do any of the list of servers in OpenStack match one of our hostnames?
    hostnames.each do |hostname|
      if (servers.include?(hostname))
        # return the instance details merged with the node_details (info like role)
        running[hostname] = servers[hostname].merge(node_details[hostname])
      end
    end

    Logger.debug { "#{running}" }
    Logger.debug { "<<< Stack.get_our_instances" }
    running
  end

  def Stack.delete_node(config, node)
    # this also populates out unspecified defaults, like az
    Stack.populate_config(config)
    # get info about all instances running in our account & AZs
    Stack.get_all_instances(config)

    if (config[:all_instances][node].nil?)
      Logger.info "Sorry, #{node} doesn't exist or isn't running"
    else
      Logger.info "Deleting node #{node} in #{config[:all_instances][node][:region]}..."
      os = Stack.connect(config, config[:all_instances][node][:region])
      instance = os.get_server(config[:all_instances][node][:id])
      instance.delete!
    end
  end

  def Stack.delete_all(config)
    # check that we have OS_* vars loaded etc
    Stack.syntax_check(config)
    # this also populates out unspecified defaults, like az
    Stack.populate_config(config)

    # get the list of nodes we consider 'ours', i.e. with hostnames that match
    # those generated by this stack
    ours = Stack.get_our_instances(config)

    # do any of the list of servers in OpenStack match one of our hostnames?
    ours.each do |node, node_details|
        Logger.info "Deleting #{node}"
        os = Stack.connect(config, config[:all_instances][node][:region])
        d = os.get_server(config[:all_instances][node][:id])
        d.delete!
    end
  end

  def Stack.set_chef_server(config, chef_server)
    # set the private & public URLs for the chef server,
    # called either after we create the Chef Server, or skip over it
    Logger.debug "Setting :chef_server_hostname, chef_server_private & chef_server_public details (using #{chef_server})"

    config[:chef_server_hostname] = chef_server
    # get the internal IP of this instance....which we should have stored in config[:all_instances]
    if config[:all_instances][chef_server] && config[:all_instances][chef_server][:addresses]
      config[:all_instances][chef_server][:addresses].each do |address|
        # find the private IP, any old private IP will do...
        if (address.label == 'private')
          config[:chef_server_private] = "http://#{address.address}:4000/"
          Logger.info "Setting the internal Chef URL to #{config[:chef_server_private]}"
        end

        # only set the public url if it hasn't been set in the config
        if ((config[:chef_server_public].nil? || config[:chef_server_public].empty?) && address.label == 'public')
          config[:chef_server_public] = "http://#{address.address}:4000/"
          Logger.info "Setting the public Chef URL to #{config[:chef_server_public]}"
        end
      end
    end
  end

  def Stack.secgroup_sync(config)
    # 1) get all the IP information we have
    # 2) generate the json to describe that to the "stackhelper secgroup-sync" tool
    # 3) run "stackhelper secgroup-sync --some-file our-ips.json"
    ours = Stack.get_our_instances(config)

    secgroup_ips = Hash.new
    # walk the list of hosts, dumping the IPs into role buckets
    ours.each do |instance, instance_details|
      secgroup_ips[instance_details[:role]] = Array.new if secgroup_ips[instance_details[:role]].nil?

      #secgroup_ips[instance_details[:role]] << instance_details[:addresses].map { |address| address.address }
      secgroup_ips[instance_details[:role]] << instance_details[:addresses].map do |address|
        if (address.label == 'public')
          address.address
        else
          next
        end
      end

      # we potentially have an array of arrays, so flatten them
      secgroup_ips[instance_details[:role]].flatten!

      # delete any nil's that we collected due to skipping private ips
      secgroup_ips[instance_details[:role]].delete_if {|x| x.nil? }
    end

    # dump the json to a temp file
    #sg_json = Tempfile.new(['secgroup_ips', '.json'])
    sg_json = File.new('secgroup_ips.json', "w")
    sg_json.write(secgroup_ips.to_json)
    sg_json.close

    if File.exists?('secgroups.json')
      Logger.info "Found secgroups.json, syncing secgroups across AZ"
      # run the secgroup-sync tool, across each AZ/REGION
      config[:azs].each do |az|
        Logger.info "Syncing security groups in #{az}"
        system("stackhelper --os-region-name #{az} secgroup-sync --secgroup-json secgroups.json --additional-group-json #{sg_json.path}")
      end
    else
      Logger.info "No secgroups.json found, skipping secgroup sync"
    end
  end

  # if we're passed a role, only deploy this role.
  def Stack.deploy_all(config, role_to_deploy = nil)
    Stack.validate(config)

    # this also populates out unspecified defaults, like az
    node_details = Stack.populate_config(config)
    # get info about all instances running in our account & AZs
    servers = Stack.get_all_instances(config)

    # this is our main loop iterator, generates each host
    config[:roles].each do |role,role_details|
      Logger.debug { "Iterating over roles, this is #{role}, role_details = #{role_details}" }

      (1..role_details[:count]).each do |p|
        hostname = Stack.generate_hostname(config, role, p)
        Logger.debug { "Iterating over nodes in #{role}, this is #{hostname}" }

        # configure the global :chef_server details if this the chef server
        if role_details[:chef_server]
          Stack.set_chef_server(config, hostname)
        end

        # does this node already exist?
        if (!servers[hostname].nil?)
          Logger.info { "#{hostname} already exists, skipping.." }
          next
        end

        Logger.debug { "Deploying #{role}, role_to_deploy = #{role_to_deploy}" }
        if ((role_to_deploy.nil?) || (role_to_deploy.to_s == role.to_s))
          if (role_details[:skip_chef_prereg] == true || role_details[:chef_server])
            Logger.debug "Skipping Chef pre-reg for #{hostname}"
          else
            # Prepare Chef
            # 1) delete the client if it exists
            knife_client_list = `knife client list | grep #{hostname}`
            knife_client_list.sub!(/\s/,'')
            if knife_client_list.length() > 0
              # we should delete the client to make way for this new machine
              Logger.info `knife client delete --yes #{hostname}`
            end

            # knife node create -d --environment $CHEF_ENVIRONMENT $SERVER_NAME
            # knife node run_list add -d --environment $CHEF_ENVIRONMENT $SERVER_NAME "role[${ROLE}]"
            # this relies on .chef matching the stacks config (TODO: poke the Chef API directly?)
            cmd = "EDITOR=\"perl -p -i -e 's/_default/#{config[:chef_environment]}/'\" knife node create --server-url #{config[:chef_server_public]} #{hostname}"
            Logger.debug cmd
            knife_node_create = `#{cmd}`
            Logger.info "Priming Chef Server: #{knife_node_create}"

            cmd = "knife node run_list add -d --environment #{config[:chef_environment]} #{hostname} \"role[#{role}]\""
            Logger.info cmd
            knife_node_run_list = `#{cmd}`
            Logger.info "Priming Chef Server: #{knife_node_run_list}"
          end

          # build the user-data content for this host
          # (we have a local copy of https://github.com/lovelysystems/cloud-init/blob/master/tools/write-mime-multipart)
          # 1) generate the mimi-multipart file
          # libdir = where our shipped scripts live
          # (use config[:stackhome] for "project" config/scripts)
          libdir = File.realpath(@@gemhome + '/lib')
          multipart_cmd = "#{libdir}/write-mime-multipart #{role_details[:bootstrap]} #{role_details[:cloud_config_yaml]}"
          Logger.debug { "multipart_cmd = #{multipart_cmd}" }
          multipart = `#{multipart_cmd}`
          Logger.debug { "multipart = #{multipart}" }

          # 2) replace the tokens (CHEF_SERVER, CHEF_ENVIRONMENT, SERVER_NAME, ROLE)
          Logger.debug { "Replacing %HOSTNAME% with #{hostname} in multipart" }
          multipart.gsub!(%q!%HOSTNAME%!, hostname)

          if config[:chef_server_hostname].nil?
            Logger.info  "config[:chef_server_hostname] is nil, skipping chef server substitution"
          else
            Logger.info  "Chef server is #{config[:chef_server_hostname]}, which is in #{config[:node_details][config[:chef_server_hostname]][:region]}"
            Logger.info  "#{hostname}'s region is #{config[:node_details][hostname][:region]}"
            # if this host is in the same region/az, use the private URL, if not, use the public url
            if (config[:node_details][hostname][:region] == config[:node_details][config[:chef_server_hostname]][:region]) && !config[:chef_server_private].nil?
              multipart.gsub!(%q!%CHEF_SERVER%!, config[:chef_server_private])
            elsif !config[:chef_server_public].nil?
              multipart.gsub!(%q!%CHEF_SERVER%!, config[:chef_server_public])
            else
              Logger.warn { "Not setting the chef url for #{hostname} as neither chef_server_private or chef_server_public are valid yet" }
            end
            multipart.gsub!(%q!%CHEF_ENVIRONMENT%!, config[:chef_environment])
            if File.exists?(config[:chef_validation_pem])
              multipart.gsub!(%q!%CHEF_VALIDATION_PEM%!, File.read(config[:chef_validation_pem]))
            else
              Logger.warn "Skipping #{config[:chef_validation_pem]} substitution in user-data"
            end
          end

          multipart.gsub!(%q!%SERVER_NAME%!, hostname)
          multipart.gsub!(%q!%ROLE%!, role.to_s)
          multipart.gsub!(%q!%DATA_DIR%!, role_details[:data_dir])

          if role_details[:bootstrap].match('\.erb$') || role_details[:cloud_config_yaml].match('\.erb$')
            Logger.debug { "bootstrap or cloud_config_yaml are erb files"}
            instances = Hash.try_convert(Stack.get_our_instances(config))
            all_instances = Hash.try_convert(Stack.get_all_instances(config))

            Logger.debug { instances }
            Logger.debug { all_instances }

            multipart_template = ERB.new(multipart)
            multipart_complete = multipart_template.result(binding)

            Logger.debug { "multipart_complete after erb => #{multipart_complete} " }
            multipart = multipart_complete
          end

          Logger.info "Creating #{hostname} in #{node_details[hostname][:az]} with role #{role}"

          # this will get put in /meta.js
          metadata = { 'region' => node_details[hostname][:az], 'chef_role' => role }

          os = Stack.connect(config, node_details[hostname][:az])
          newserver = os.create_server(:name => hostname,
                                       :imageRef => config[node_details[hostname][:az]]['image_id'],
                                       :flavorRef => config['flavor_id'],
                                       :security_groups=>[role_details[:security_group]],
                                       :user_data => Base64.encode64(multipart),
                                       :metadata => metadata,
                                       :key_name => config[:key_pair])

          # wait for the server to become ACTIVE before proceeding
          while (newserver.status != 'ACTIVE') do
            print '.'
            sleep 1
            # refresh the status
            newserver.refresh
          end
          puts

          # refresh the config[:all_instances] with the newly built server
          # TODO: we should be able to just add this server, instead of re-polling everything
          Stack.get_all_instances(config, true)

          # refresh the chef_server details..we should have IPs now
          if role_details[:chef_server]
            Stack.set_chef_server(config, hostname)
            Stack.generate_knife_rb(config)
          end

          # attach a floating IP to this if we have one
          if role_details[:floating_ips] && role_details[:floating_ips][p-1]
            floating_ip = role_details[:floating_ips][p-1]
            Logger.info "Attaching #{floating_ip} to  #{hostname}\n via 'nova add-floating-ip'"
            # nova --os-region-name $REGION add-floating-ip $SERVER_NAME $FLOATING_IP
            floating_ip_add = `nova --os-region-name #{node_details[hostname][:az]} add-floating-ip #{hostname} #{floating_ip}`
            Logger.info floating_ip_add
          end

          # refresh the secgroups ASAP
          Stack.secgroup_sync(config)

          # run any post-install scripts, these are run from the current host, not the nodes
          if role_details[:post_install_script]
            Logger.debug { "This role has a post-install script (#{role_details[:post_install_script]}), preparing to run" }
            # convert when we got passed to an absolute path
            post_install_script_abs = File.realpath(config[:stackhome] + '/' + role_details[:post_install_script])
            post_install_cwd_abs = File.realpath(config[:stackhome] + '/' + role_details[:post_install_cwd])

            # replace any tokens in the argument
            public_ip = Stack.get_public_ip(config, hostname)
            post_install_args = role_details[:post_install_args].sub(%q!%PUBLIC_IP%!, public_ip)

            # we system this, so that the script can give live feed back
            Logger.info "Executing '#{post_install_script_abs} #{post_install_args}' in #{post_install_cwd_abs} as the post_install_script"
            system("cd #{post_install_cwd_abs} ; #{post_install_script_abs} #{post_install_args}")
          end
        else
          Logger.info "Skipped role #{role}"
        end
      end
    end
  end

  def Stack.find_file(config, filename)
    # find a file, using the standard path precedence
    # 1) cwd
    # 2) stackhome
    # 3) gemhome/lib
    dirs = [ './' ]
    dirs.push(config[:stackhome])
    dirs.push(@@gemhome + '/lib')

    Logger.debug "find_file, looking for #{filename} in #{dirs}"
    filename_fqp = ''
    dirs.each do |dir|
      fqp = dir + '/' + filename
      Logger.debug "find_file: checking #{fqp}"
      if File.file?(fqp)
      Logger.debug "find_file: found #{fqp}!"
        filename_fqp =  File.expand_path(fqp)
      end
    end

    if filename_fqp.empty?
      Logger.warn "couldn't find #{filename} in #{dirs}"
    end
    filename_fqp
  end

end

