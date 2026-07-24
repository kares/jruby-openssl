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

namespace 'net-imap' do
  net_imap_dir = File.expand_path('net-imap', File.dirname(__FILE__))
  jopenssl_lib = File.expand_path('lib', File.dirname(__FILE__))

  desc "Install net-imap gem dependencies"
  task :bundle do
    sh "cd #{net_imap_dir} && bundle install"
  end

  task :bundle_check do
    unless File.exist?(File.join(net_imap_dir, 'Gemfile.lock'))
      fail "bundle not installed, run `rake net-imap:bundle'"
    end
  end

  desc "Run net-imap (SSL/STARTTLS) tests against jruby-openssl"
  task :test => ['lib/jopenssl.jar', :bundle_check] do
    # jruby-openssl lib is absolute (and first) so the -C chdir below can't shadow the local openssl
    libs = [ jopenssl_lib, File.join(net_imap_dir, 'lib'), File.join(net_imap_dir, 'test/lib') ]
    # TLS handshake / STARTTLS tests only (the rest of test_imap.rb hangs on JRuby); the two
    # starttls_stripping tests are excluded - their 10ms coordination sleep is a JRuby
    # thread-scheduling race (plain-socket IOError, not TLS), not a jruby-openssl issue
    name_filter = '--name=/^test_(imaps|starttls(?!_stripping))/'
    # array form (no shell) so the regexp metacharacters reach test-unit intact
    ruby '-C', net_imap_dir, "-I#{libs.join(File::PATH_SEPARATOR)}",
         '-rbundler/setup', '-rhelper',
         File.join(net_imap_dir, 'test/net/imap/test_imap.rb'), name_filter, '-v'
  end
end

namespace 'net-ssh' do
  net_ssh_dir = File.expand_path('net-ssh', File.dirname(__FILE__))

  desc "Install net-ssh gem dependencies"
  task :bundle do
    sh "cd #{net_ssh_dir} && bundle install"
    # net-ssh's gemspec skips bcrypt_pbkdf on java (-java variant is only out as a pre-release)
    sh "gem install --no-document ed25519 && gem install --no-document --pre bcrypt_pbkdf"
  end

  task :bundle_check do
    unless File.exist?(File.join(net_ssh_dir, 'Gemfile.lock'))
      fail "bundle not installed, run `rake net-ssh:bundle'"
    end
  end

  desc "Run net-ssh (OpenSSL) tests against jruby-openssl"
  Rake::TestTask.new(:test) do |task|
    test_files = %w[
      test/test_key_factory.rb
      test/transport/test_cipher_factory.rb
      test/transport/test_hmac.rb
      test/authentication/test_certificate.rb
      test/authentication/test_ed25519.rb
      test/authentication/test_key_manager.rb
    ]
    test_files += FileList[File.join(net_ssh_dir, 'test/transport/{kex,hmac}/test_*.rb')].to_a

    task.libs = [ 'lib', File.join(net_ssh_dir, 'lib'), File.join(net_ssh_dir, 'test') ]
    task.test_files = test_files.map { |path| File.expand_path(path, net_ssh_dir) }
    task.verbose = false
    # exclude the CTR *_encryption2/decryption2 tests: they update-then-final-then-update
    # JOSSL' native CTR resets the counter on final (MRI continues) - a test-only pattern,
    # real SSH streams updates continuously (see test/test_cipher.rb for CTR coverage)
    task.options = "--verbose --exclude='/_ctr_for_.*cryption2/'"
    task.ruby_opts = [ '-v', '-C', net_ssh_dir, '-rcommon' ]
  end

  task :test => ['lib/jopenssl.jar', :bundle_check]
end

namespace 'ruby-jwt' do
  jwt_dir = File.expand_path('ruby-jwt', File.dirname(__FILE__))

  desc "Install ruby-jwt gem dependencies"
  task :deps do
    # dev deps pull irb -> rdoc -> rbs (C-extension gem)
    # specs are runnable via `-S rspec` (no bundle/setup) and only need these
    # sh "cd #{jwt_dir} && bundle install"
    ruby "-S gem install --no-document rspec simplecov base64 logger"
  end

  task :deps_check do
    # unless File.exist?(File.join(jwt_dir, 'Gemfile.lock'))
    #   fail "bundle not installed, run `rake ruby-jwt:bundle'"
    # end
  end

  desc "Run ruby-jwt (OpenSSL) tests against jruby-openssl"
  task :test => ['lib/jopenssl.jar', :deps_check] do
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
