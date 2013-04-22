# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'stack-kicker/version'

Gem::Specification.new do |gem|
  gem.name          = "stack-kicker"
  gem.version       = Stack::Kicker::VERSION
  gem.authors       = ["Simon McCartney"]
  gem.email         = ["simon.mccartney@hp.com"]
  gem.description   = %q{application stack management tool for OpenStack}
  gem.summary       = %q{applicarion stack management tool for OpenStack that uses stock images & chef-server to kick the instance into shape}
  gem.homepage      = "https://github.com/simonmcc/stack-kicker"

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]
  gem.add_development_dependency('rdoc')
  gem.add_development_dependency('aruba')
  gem.add_development_dependency('rake', '~> 0.9.2')
  gem.add_dependency('methadone', '~> 1.2.4')
  gem.add_dependency('openstack', '~> 1.0.9')
  # this is a hack - or potentially dangerous, can we access teh API without installing all of the chef gem?
  gem.add_dependency('chef', '~> 10.18')
end
