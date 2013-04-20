# stack-kicker

stack-kicker is a simple 'application stack' deployment tool, it's purpose in life 
is to spin up a set of instances in a repeatable, controlled fashion, and optionally 
run post-install scripts after each instance has been started.

stack-kicker has hooks to allow default & custom cloud-init templates to be built & passed to
your compute provider (we currently use ruby-openstack, so are limited to OpenStack providers, 
however, a sister project, aws-kicker, uses fog.io, the interaction with the compute provider is
minimal, so it's on the roadmap to merge aws-kicker & stack-kicker, and use either an internal
abstraction layer or just fog.io for all compute provisioning requests)

## Stackfile
Normally, stack configurations are stored in a Stackfile, which is a ruby hash of configuration options.
Typically, the Stackfile contains the following sets of information

1. Credentials for your compute provider
2. Defaults for your Stack (compute flavor, image id, region/az, ssh-keys, instance name template)
1. roles

## Concepts
stack-kicker sequentially iterates over defined roles, creating the required number of nodes (nodes are the compute instances).  If an instance already exists with the proposed name, it's skipped, assuming that this node has already been built.

Hostnames are generated from a customizable template, which is effectively:

	config[:name_template] = '%s-%s-%s%04d'
	config['global_service_name'] = 'myapp'
	site = <derived from region/az, via config[:site_template]>
	hostname = sprintf(config[:name_template], config['global_service_name'], site, role, position)

So hostnames will be myapp-az1-chef0001, myapp-az1-web0001, myapp-az1-web0002 etc. 

post-install scripts are executed from the same host as stack-kicker is being used, using the same credentials as the current user.  They are can be used to retrieve information from a freshly built node (like certificates from a chef server), so block progress until the chef-client run has completed (we use this to block percona/galera & rabbitmq cluster builds so that the first node is up & running correctly before we try and add another node to the cluster)

## Example workflows/models
stack-kicker was built with the following workflows in mind:

### private chef-server
This was the original requirement, a multi-role application stack build that started
with building a chef-server, uploading roles, environments, cookbooks & databags to it,
and then building the rest of the application-stack instances, using the freshly built chef-server
to drop the application on to the instances.  In this setup we used vanilla images (Ubuntu 12.04 LTS, 
but you could use any image, either vanilla or pre-populated with your software).

Here's an example Stackfile for this:
	
	module StackConfig
		Stacks = {
	    'web-w-chef-server' => {
	      # (we can access environment variable via ENV['foo'] instead of hard coding u/p here)
	      'REGION'      => ENV['OS_REGION_NAME'],
	      'USERNAME'    => ENV['OS_USERNAME'],
	      'PASSWORD'    => ENV['OS_PASSWORD'],
	      'AUTH_URL'    => ENV['OS_AUTH_URL'],
	      'TENANT_NAME' => ENV['OS_TENANT_NAME'],
	
	       # generic instance info
	       'flavor_id'  => 103,
	       'image_id'   => 75845,
	       :key_pair => 'ssh-keypair-name',
	       :key_public => '/path/to/id_rsa.pub',
	       :global_service_name => 'perconaconf',
	       
	       # role details
	       :roles => {
	         # override the default cloud-init script & default bootstrap (which is a chef-client bootstrap)
	         :chef => {
	            # we are the chef server, so skip the chef-client steps
	           :chef_server => true,	:skip_chef_prereg => true,
	           # override the default cloud-config with a chef-server template
	           :cloud_config_yaml => 'chef-cloud-config.yaml',
	           # skip the default chef-client bootstrap
	           :bootstrap => '',                                 
	           # wait for the chef server to come up & download pem files & generate client account
	           :post_install_script => 'bootstrap/chef-post-install.sh',
	            # our post install script dumps out .pem files in the CWD   
	           :post_install_cwd => '.chef',                    
	           # The post-install script needs to know the public IP of the just built instance so that this station can access it
	           :post_install_args => '%PUBLIC_IP%'               
	         },
	         # much simpler role, just build 3 of these, chef-client will do the rest on boot
	         :web => {  :count => 3 }
	       }
	    }
	    }
	end
           

### simple roles
There is no requirement that stack-kicker do anything other than spin up your instances, your requirements 
may be such that you just need a number of instances started with certain images, region & flavor requirements.

### masterless puppet
aws-kicker (a sister project) had an original requirement of starting a simple 2-tier web application in multiple 
locations/environments (prod, stage, dev etc), to do this we configured the instances by bootrapping puppet, 
git clonig /etc/puppet and running "puppet apply", a simple pattern used in many places, this was all achievd with a
carefully crafted cloud-init template (incidentally, this also allowed for simple prototyping using vagrant to
provide local instances using the exact same '/etc/puppet' git repo.

### Other workflows
These are only the workflows I've used, there is no reason a puppet master couldn't be built & used, or 
hosted/external puppet & chef servers. (pull requests accepted etc, including salt, ansible, cfengine etc..)

## Installation

    $ gem install stack-kicker
    
## Requirements
In addition to the the ruby dependencies which gem will install for you, access to python-novaclient is currently required to attach floating-ips to instances.

## Usage

	Usage: stack-kicker [options] task
	
	Options:
	    -h, --help                       Show command line help
	        --stackfile Stackfile        Specify an alternative Stackfile
	                                     (default: Stackfile)
	        --stack mystack              Specify the stack in Stackfile that you want to work with
	        --ssh-user USER              User to be used for SSH access
	        --version                    Show help/version info
	        --log-level LEVEL            Set the logging level
	                                     (debug|info|warn|error|fatal)
	                                     (Default: info)
	
	Arguments:

    task
        task to be performed validate|configure-knife|show-stacks|show-stack|show-running|build|replace|delete|secgroup-sync|ssh

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
