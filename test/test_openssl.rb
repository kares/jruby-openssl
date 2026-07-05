require File.expand_path('test_helper', File.dirname(__FILE__))

require 'openssl'

class TestOpenSSL < TestCase

  # only test this when the gem is installed - i.e. during integration tests
  def test_gem_version
    assert_equal ENV['BC_VERSION'], Java::OrgBouncycastleJceProvider::BouncyCastleProvider.new.info.sub( /[^0-9.]*/, '' )
    # we have a jruby-openssl gem loaded
    if spec = Gem.loaded_specs[ 'jruby-openssl' ]
      assert spec.full_gem_path.match( /!/ ) == nil
    end
  end if ENV['BC_VERSION']

  def test_version
    assert_equal String, OpenSSL::VERSION.class
    assert /\d\.\d\.\d/ =~ OpenSSL::VERSION, OpenSSL::VERSION

    assert OpenSSL::OPENSSL_VERSION.index('OpenSSL')
    if defined? JRUBY_VERSION
      assert_equal 0, OpenSSL::OPENSSL_VERSION.index('JRuby-OpenSSL ')
    end
    assert OpenSSL::OPENSSL_VERSION_NUMBER

    # MRI 2.3 openssl/utils.rb does this (and we shall pass) :
    assert defined?(OpenSSL::OPENSSL_LIBRARY_VERSION)
    assert /\AOpenSSL +0\./ !~ OpenSSL::OPENSSL_LIBRARY_VERSION
  end

  # some gems check this - better to be conservative until 3.0.0 APIs are fully supported
  def test_version_lt_3_0_0
    assert OpenSSL::OPENSSL_VERSION_NUMBER < 3 * 0x10000000
  end

  def test_debug
    debug = OpenSSL.debug
    assert (OpenSSL.debug == true || OpenSSL.debug == false)
    assert OpenSSL.debug= true
    assert_equal true, OpenSSL.debug
  ensure
    OpenSSL.debug = debug
  end

  def test_stubs
    OpenSSL.deprecated_warning_flag
    OpenSSL.check_func(:func, :header)
  end

  def test_fips_mode
    if fips?
      assert_equal true, OpenSSL.fips_mode
      OpenSSL.fips_mode = true
      assert_equal true, OpenSSL.fips_mode
    else
      assert_equal false, OpenSSL.fips_mode
      OpenSSL.fips_mode = false
      assert_equal false, OpenSSL.fips_mode
    end
  end

  def test_Digest
    digest = OpenSSL.Digest('MD5')
    assert_equal OpenSSL::Digest::MD5, digest
  end

end
