begin
  gem 'test-unit'
rescue LoadError
  warn "gem 'test-unit' not available, will load built-in 'test/unit'"
end

if bc_version = ENV['BC_VERSION']
  require 'jar-dependencies'
  require_jar 'org.bouncycastle', 'bcpkix-jdk15on', bc_version
  require_jar 'org.bouncycastle', 'bcprov-jdk15on', bc_version
  Jars.freeze_loading if defined? Jars.freeze_loading

  puts org.bouncycastle.jce.provider::BouncyCastleProvider.new.info if $VERBOSE
else
  # base_dir = File.expand_path('../../..', File.dirname(__FILE__))
  #
  # jar = File.join(base_dir, 'lib/jopenssl.jar')
  # fail("jopenssl.jar jar not found") unless jar # $CLASSPATH << jar

  # jar = Dir[File.join(base_dir, 'vendor/org/bouncycastle/**/bcprov-*.jar')].first
  # raise "bcprov jar not found" unless jar; $CLASSPATH << jar
  # jar = Dir[File.join(base_dir, 'vendor/org/bouncycastle/**/bcpkix-*.jar')].first
  # raise "bcpkix jar not found" unless jar; $CLASSPATH << jar
end if defined? JRUBY_VERSION

require 'test/unit'
TestCase = Test::Unit::TestCase

class TestCase

  def setup; require 'openssl' end

  alias assert_raise assert_raises unless method_defined?(:assert_raise)

  def assert_pkey_error(&block)
    assert_raise_kind_of(OpenSSL::PKey::PKeyError, &block)
  end

  unless method_defined?(:skip)
    if method_defined?(:omit)
      alias skip omit
    else
      def skip(msg = nil)
        warn "Skipped: #{caller[0]} #{msg}"
      end
    end
  end

  unless method_defined?(:assert_not_equal)
    def assert_not_equal(expected, actual)
      assert expected != actual, "expected: #{expected} to not equal: #{actual} but did"
    end
  end

  unless method_defined?(:assert_nothing_raised)
    def assert_nothing_raised
      begin
        yield
      rescue => e
        assert false, "unexpected error raised: #{e.inspect}"
      end
    end
  end

  unless method_defined?(:assert_not_same)
    def assert_not_same(expected, actual)
      assert ! expected.equal?(actual), "expected: #{expected} to be same as: #{actual} but did"
    end
  end

  def self.java8?; java_version.last.to_i == 8 end

  def self.java_version
    return [] unless defined? JRUBY_VERSION
    ENV_JAVA['java.specification.version'].split('.')
  end

  def self.jruby?; !!defined?(JRUBY_VERSION) end
  def jruby?; self.class.jruby? end

  def self.fips?; !!defined?(JOpenSSL::BOUNCY_CASTLE_FIPS_VERSIONS) end
  def fips?; self.class.fips? end

  private

  def debug(msg); puts msg if $VERBOSE end

  def issue_cert(dn, key, serial, extensions, issuer, issuer_key, not_before: nil, not_after: nil, digest: 'sha256')
    cert = OpenSSL::X509::Certificate.new
    issuer = cert unless issuer
    issuer_key = key unless issuer_key
    cert.version = 2
    cert.serial = serial
    cert.subject = dn
    cert.issuer = issuer.subject
    cert.public_key = key
    now = Time.now
    cert.not_before = not_before || now - 3600
    cert.not_after = not_after || now + 3600
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = issuer
    extensions.each do |oid, value, critical|
      cert.add_extension ef.create_extension(oid, value, critical)
    end
    cert.sign(issuer_key, digest)
    cert
  end

  def issue_crl(revoke_info, serial, lastup, nextup, extensions, issuer, issuer_key, digest)
    crl = OpenSSL::X509::CRL.new
    crl.issuer = issuer.subject
    crl.version = 1
    crl.last_update = lastup
    crl.next_update = nextup
    revoke_info.each{|rserial, time, reason_code|
      revoked = OpenSSL::X509::Revoked.new
      revoked.serial = rserial
      revoked.time = time
      enum = OpenSSL::ASN1::Enumerated(reason_code)
      ext = OpenSSL::X509::Extension.new("CRLReason", enum)
      revoked.add_extension(ext)
      crl.add_revoked(revoked)
    }
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.issuer_certificate = issuer
    ef.crl = crl
    crlnum = OpenSSL::ASN1::Integer(serial)
    crl.add_extension(OpenSSL::X509::Extension.new("crlNumber", crlnum))
    extensions.each do |oid, value, critical|
      crl.add_extension ef.create_extension(oid, value, critical)
    end
    crl.sign(issuer_key, digest)
    crl
  end

  def get_subject_key_id(cert)
    asn1_cert = OpenSSL::ASN1.decode(cert)
    tbscert   = asn1_cert.value[0]
    pkinfo    = tbscert.value[6]
    publickey = pkinfo.value[1]
    pkvalue   = publickey.value
    OpenSSL::Digest::SHA1.hexdigest(pkvalue).scan(/../).join(":").upcase
  end

  module Fixtures
    module_function

    def pkey(name)
      OpenSSL::PKey.read(read_file("pkey", name))
    end

    def pkey_dh(name)
      # DH parameters can be read by OpenSSL::PKey.read atm
      OpenSSL::PKey::DH.new(read_file("pkey", name))
    end

    @@__fixtures_cache = {}

    def read_file(category, name)
      @@__fixtures_cache[ [category, name] ] ||=
          File.read(File.join(File.dirname(__FILE__), "fixtures", category, name))
    end
  end
end

begin
  gem 'mocha'
rescue LoadError => e
  warn "#{e} to run all tests please `gem install mocha'"
else
  begin
    if defined? MiniTest
      require 'mocha/mini_test'
    else
      require 'mocha/test_unit'
    end
  rescue LoadError => e
    warn "current mocha version might not work (try `gem install mocha'): #{e}"
  end
end

