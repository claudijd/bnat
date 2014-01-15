# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'bnat/version'

Gem::Specification.new do |gem|
  gem.name          = "bnat"
  gem.version       = Bnat::VERSION
  gem.authors       = ["Jonathan Claudius"]
  gem.email         = ["claudijd@yahoo.com"]
  gem.description   = %q{A suite of tools focused on detecting/exploiting/fixing publicly available BNAT scenerios}
  gem.summary       = %q{A suite of tools focused on detecting/exploiting/fixing publicly available BNAT scenerios}
  gem.homepage      = ""

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

  gem.add_dependency 'packetfu', '>= 1.1.10'
  gem.add_dependency 'pcaprub'
  gem.add_dependency 'network_interface'
  gem.add_dependency 'netaddr'

  gem.add_development_dependency 'bundler'
  gem.add_development_dependency 'rake'
  gem.add_development_dependency 'rspec'
end
