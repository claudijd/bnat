# -*- encoding: utf-8 -*-
require 'rubygems'
require 'rake'
require 'rubygems/package_task'
require 'rspec'
require 'rspec/core'
require 'rspec/core/rake_task'

$:.unshift File.join(File.dirname(__FILE__), "lib")

require 'bnat'

task :default => :spec

desc "Run all specs in spec directory"
RSpec::Core::RakeTask.new(:spec)

def clean_up
  Dir.glob("*.gem").each { |f| File.unlink(f) }
  Dir.glob("*.lock").each { |f| File.unlink(f) }  
end

desc "Build the gem"
task :build do
  puts "[+] Building BNAT version #{BNAT::VERSION}"
  puts `gem build bnat.gemspec`
end

desc "Publish the gem"
task :publish do
  puts "[+] Publishing BNAT version #{BNAT::VERSION}"  
  Dir.glob("*.gem").each { |f| puts `gem push #{f}`} 
end

desc "Tag the release"
task :tag do
  puts "[+] Tagging BNAT version #{BNAT::VERSION}"  
  `git tag #{BNAT::VERSION}`
  `git push --tags`
end

desc "Bump the Gemspec Version"
task :bump do
  puts "[+] Bumping BNAT version #{BNAT::VERSION}"
  `git commit -a -m "Bumped Gem version to #{BNAT::VERSION}"`
  `git push origin master`
end

desc "Perform an end-to-end release of the gem"
task :release do
  clean_up() # Clean up before we start
  Rake::Task[:build].execute
  Rake::Task[:bump].execute
  Rake::Task[:tag].execute
  Rake::Task[:publish].execute
  clean_up() # Clean up after we complete
end
