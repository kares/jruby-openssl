require 'rake/testtask'

mvnw = File.expand_path('./mvnw', File.dirname(__FILE__))

# reproducible build: SOURCE_DATE_EPOCH shared by jopenssl.jar and gem
# read from env by RubyGems; pass via -D so dev builds don't churn pom.xml
def source_date_epoch!
  ENV['SOURCE_DATE_EPOCH'] ||= `git log -1 --pretty=%ct`.strip
end

def _build_output_timestamp
  "-Dproject.build.outputTimestamp=#{ENV['SOURCE_DATE_EPOCH']}" if ENV['SOURCE_DATE_EPOCH']
end

desc "Package jopenssl.jar with the compiled classes"
task :jar do
  sh("#{mvnw} prepare-package -Dmaven.test.skip=true")
end

task :test_prepare => :jar do
  sh("#{mvnw} test-compile") # separate due -Dmaven.test.skip=true
end

task :clean do
  sh("#{mvnw} clean")
end

task :build do
  source_date_epoch!
  sh("#{mvnw} package #{_build_output_timestamp}")
end

desc "Sanity-check the tree/version, then build a reproducible release gem"
task :release => :release_check do
  source_date_epoch! # pin to the release commit so the gem + jar use the same
  puts "SOURCE_DATE_EPOCH=#{ENV['SOURCE_DATE_EPOCH']} (#{Time.at(ENV['SOURCE_DATE_EPOCH'].to_i).utc})"
  Rake::Task[:build].invoke
  gem = Dir['target/*.gem', 'pkg/*.gem'].max_by { |f| File.mtime(f) }
  abort "release aborted - no .gem produced" unless gem
  puts "built #{gem}"
  # gem push #{gem}  (or: #{File.basename(mvnw)} deploy -Pjar-release for the jar artifact)"
end

task :release_check do
  dirty = `git status --porcelain`.strip
  abort "release aborted - working tree is not clean:\n#{dirty}" unless dirty.empty?

  load File.expand_path('lib/jopenssl/version.rb', File.dirname(__FILE__))
  version = JOpenSSL::VERSION

  if Gem::Version.new(version).prerelease? && ENV['PRERELEASE'] != 'true'
    abort "release aborted - #{version} is a prerelease"
  end

  branch = `git rev-parse --abbrev-ref HEAD`.strip
  warn "WARNING: releasing from '#{branch}' (not 'master')" unless branch == 'master'

  tag = `git tag --points-at HEAD`.split("\n").find { |t| t =~ /#{Regexp.escape(version)}/ }
  warn "WARNING: no git tag matching #{version} points at HEAD" unless tag

  puts "release checks passed for #{version}"
end

desc "Build the self-contained jar-release artifacts (-Pjar-release)"
task :jar_release => :release_check do
  source_date_epoch!
  puts "SOURCE_DATE_EPOCH=#{ENV['SOURCE_DATE_EPOCH']} (#{Time.at(ENV['SOURCE_DATE_EPOCH'].to_i).utc})"
  sh("#{mvnw} package -Pjar-release -Dmaven.test.skip=true #{_build_output_timestamp}")
  # deploy (gpg-sign + push): #{File.basename(mvnw)} deploy -Prelease,jar-release -D...
end

task :default => :build

file('lib/jopenssl.jar') { Rake::Task[:jar].invoke }

file('pkg/test-classes/org/jruby/ext/openssl/SecurityHelperTest.class') do
  Rake::Task[:test_prepare].invoke
end

Rake::TestTask.new do |task|
  task.libs << File.expand_path('test', File.dirname(__FILE__))
  test_files = FileList['test/**/test*.rb'].to_a
  task.test_files = test_files.map { |path| path.sub('test/', '') }
  task.verbose = false # using -v directly instead due issues with rake
  task.loader = :direct
  task.ruby_opts = [ '-v', '-rbundler/setup' ]
end
task :test => ['lib/jopenssl.jar', 'pkg/test-classes/org/jruby/ext/openssl/SecurityHelperTest.class']

require_relative 'tasks/vendor_tests'
define_vendor_test_tasks # root + jopenssl_lib default to this tree

namespace :integration do
  it_path = File.expand_path('src/test/integration', File.dirname(__FILE__))
  task :install do
    ruby "-C #{it_path} -S bundle install"
  end
  # desc "Run IT tests"
  task :test => 'lib/jopenssl.jar' do
    unless File.exist?(File.join(it_path, 'Gemfile.lock'))
      raise "bundle not installed, run `rake integration:install'"
    end
    loader = "ARGV.each { |file| require(file) }"
    lib = [ File.expand_path('../lib', __FILE__), it_path ]
    test_files = FileList['src/test/integration/*_test.rb'].map { |path| path.sub('src/test/integration/', '') }
    ruby "-I#{lib.join(':')} -C src/test/integration -e \"#{loader}\" #{test_files.map { |f| "\"#{f}\"" }.join(' ')}"
  end
end
