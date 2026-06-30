require 'rake/testtask'

mvnw = File.expand_path('./mvnw', File.dirname(__FILE__))

desc "Package jopenssl.jar with the compiled classes"
task :jar do
  sh("#{mvnw} prepare-package -Dmaven.test.skip=true")
end
namespace :jar do
  desc "Package jopenssl.jar file (and dependent jars)"
  task :all do
    sh("#{mvnw} package -Dmaven.test.skip=true")
  end
end
task :test_prepare => :jar do
  sh("#{mvnw} test-compile") # separate due -Dmaven.test.skip=true
end

task :clean do
  sh("#{mvnw} clean")
end

task :build do
  sh("#{mvnw} package")
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

namespace 'net-http' do
  net_http_dir = File.expand_path('net-http', File.dirname(__FILE__))

  desc "Install net-http gem dependencies"
  task :bundle do
    sh "cd #{net_http_dir} && bundle install --without sig"
  end

  desc "Run net-http HTTPS tests against jruby-openssl"
  Rake::TestTask.new(:test) do |task|
    task.libs = [ 'lib', File.join(net_http_dir, 'lib'), File.join(net_http_dir, 'test/lib') ]
    test_files = %w[test/net/http/test_https.rb test/net/http/test_https_proxy.rb]
    task.test_files = test_files.map { |path| File.expand_path(path, net_http_dir) }
    task.verbose = false
    task.loader = :direct
    task.ruby_opts = [ '-v', '-C', net_http_dir, '-rhelper' ]
  end

  task :test => ['lib/jopenssl.jar']
end

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
