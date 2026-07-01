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

  task :bundle_check do
    unless File.exist?(File.join(net_http_dir, 'Gemfile.lock'))
      fail "bundle not installed, run `rake net-http:bundle'"
    end
  end

  desc "Run net-http (HTTPS) tests against jruby-openssl"
  Rake::TestTask.new(:test) do |task|
    task.libs = [ 'lib', File.join(net_http_dir, 'lib'), File.join(net_http_dir, 'test/lib') ]
    test_files = %w[test/net/http/test_https.rb test/net/http/test_https_proxy.rb]
    task.test_files = test_files.map { |path| File.expand_path(path, net_http_dir) }
    task.verbose = false
    task.loader = :direct
    task.ruby_opts = [ '-v', '-C', net_http_dir, '-rhelper' ]
  end

  task :test => ['lib/jopenssl.jar', :bundle_check]
end

namespace 'ruby-jwt' do
  jwt_dir = File.expand_path('ruby-jwt', File.dirname(__FILE__))

  desc "Install ruby-jwt gem dependencies"
  task :bundle do
    sh "cd #{jwt_dir} && bundle install"
  end

  task :bundle_check do
    unless File.exist?(File.join(jwt_dir, 'Gemfile.lock'))
      fail "bundle not installed, run `rake ruby-jwt:bundle'"
    end
  end

  desc "Run ruby-jwt (OpenSSL) tests against jruby-openssl"
  task :test => ['lib/jopenssl.jar', :bundle_check] do
    lib_path = File.expand_path('lib', File.dirname(__FILE__))
    spec_files = [
      'spec/jwt/jwt_spec.rb',
      'spec/jwt/jwa_spec.rb',
      'spec/jwt/jwa/ecdsa_spec.rb',
      'spec/jwt/jwa/hmac_spec.rb',
      'spec/jwt/jwa/rsa_spec.rb',
      'spec/jwt/jwk_spec.rb',
      'spec/jwt/jwk/decode_with_jwk_spec.rb',
      'spec/jwt/jwk/ec_spec.rb',
      'spec/jwt/jwk/rsa_spec.rb',
      'spec/jwt/x5c_key_finder_spec.rb',
      'spec/integration/readme_examples_spec.rb'
    ].map { |file| File.expand_path(file, jwt_dir) }

    ruby "-C #{jwt_dir} -I#{lib_path} -S rspec -I#{lib_path} #{spec_files.join(' ')}"
  end
end

namespace 'sigstore' do
  sigstore_dir = File.expand_path('sigstore-ruby', File.dirname(__FILE__))

  desc "Install sigstore-ruby gem dependencies"
  task :bundle do
    sh "cd #{sigstore_dir} && bundle install"
  end

  task :bundle_check do
    unless File.exist?(File.join(sigstore_dir, 'Gemfile.lock'))
      fail "bundle not installed, run `rake sigstore:bundle'"
    end
  end

  desc "Run sigstore-ruby (OpenSSL) tests against jruby-openssl"
  Rake::TestTask.new(:test) do |task|
    test_files = FileList[File.join(sigstore_dir, 'test/sigstore/**/*_test.rb')].to_a
    test_files = test_files.reject { |f| f.include?('conformance_test') }

    task.libs = [ File.expand_path('lib', File.dirname(__FILE__)), File.join(sigstore_dir, 'lib'), File.join(sigstore_dir, 'test') ]
    task.test_files = test_files.map { |path| File.expand_path(path, sigstore_dir) }
    task.verbose = false
    task.loader = :direct
    task.ruby_opts = [ '-v', '-C', sigstore_dir, '-rbundler/setup', '-rtest_helper' ]
  end

  task :test => ['lib/jopenssl.jar', :bundle_check]
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
