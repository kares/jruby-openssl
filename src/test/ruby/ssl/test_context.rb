# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestSSLContext < TestCase
  #include SSLTestHelper

  def test_methods
    methods = OpenSSL::SSL::SSLContext::METHODS
    assert methods.include?(:SSLv3)
    assert methods.include?(:'TLSv1_1')
    assert ! methods.include?(:'TLSv1.1')

    assert methods.include?(:'TLSv1_1_client')
    assert methods.include?(:'TLSv1_1_server')

    assert methods.include?(:'TLSv1_2')
    assert methods.include?(:'TLSv1_2_client')
    assert methods.include?(:'TLSv1_2_server')
  end

  def test_context_new
    OpenSSL::SSL::SSLContext.new

    OpenSSL::SSL::SSLContext.new :SSLv3
    assert_raises ArgumentError do
      OpenSSL::SSL::SSLContext.new "TLSv42"
    end
  end

  def test_setup
    ctx = OpenSSL::SSL::SSLContext.new
    assert_equal(ctx.setup, true)
    assert_equal(ctx.setup, nil)

    m = OpenSSL::SSL::SSLContext::METHODS.first

    ex = assert_raise(ArgumentError) do
      OpenSSL::SSL::SSLContext.new("#{m}\0")
    end
    # ex.message =~ /null/
    ex = assert_raise(ArgumentError) do
      OpenSSL::SSL::SSLContext.new("\u{ff33 ff33 ff2c}")
    end
    assert ex.message =~ /\u{ff33 ff33 ff2c}/
  end

  def test_default_handling # GH-2193 JRuby
    ctx = OpenSSL::SSL::SSLContext.new
    assert_nothing_raised { ctx.ciphers = "DEFAULT:!aNULL" }
  end

  def test_verify_mode
    context = OpenSSL::SSL::SSLContext.new
    assert_nil context.verify_mode
    context = OpenSSL::SSL::SSLContext.new :SSLv3
    assert_nil context.verify_mode

    server_cert = OpenSSL::X509::Certificate.new IO.read( File.join(File.dirname(__FILE__), 'server.crt') )
    server_key = OpenSSL::PKey::RSA.new IO.read( File.join(File.dirname(__FILE__), 'server.key') )

    context = OpenSSL::SSL::SSLContext.new.tap do |ctx|
      ctx.cert = server_cert ; ctx.key  = server_key
    end
    assert_nil context.verify_mode

    client_cert = OpenSSL::X509::Certificate.new IO.read( File.join(File.dirname(__FILE__), 'client.crt') )
    client_key = OpenSSL::PKey::RSA.new IO.read( File.join(File.dirname(__FILE__), 'client.key') )

    context = OpenSSL::SSL::SSLContext.new.tap do |ctx|
      ctx.cert = client_cert ; ctx.key  = client_key
    end
    assert_nil context.verify_mode
  end

  def test_context_set_ssl_version
    context = OpenSSL::SSL::SSLContext.new
    context.ssl_version = "TLSv1"

    context = OpenSSL::SSL::SSLContext.new
    context.ssl_version = :SSLv3

    context = OpenSSL::SSL::SSLContext.new
    context.ssl_version = :"TLSv1_1" unless RUBY_VERSION < '2.0'
    #assert_equal :TLSv1_1, context.ssl_version

    context = OpenSSL::SSL::SSLContext.new
    context.ssl_version = "TLSv1_1" unless RUBY_VERSION < '2.0'

    context = OpenSSL::SSL::SSLContext.new
    context.ssl_version = "TLSv1.1" if defined? JRUBY_VERSION

    context = OpenSSL::SSL::SSLContext.new
    context.ssl_version = :TLSv1_2 unless RUBY_VERSION < '2.0'

    context = OpenSSL::SSL::SSLContext.new
    context.ssl_version = "TLSv1.2" if defined? JRUBY_VERSION

    context = OpenSSL::SSL::SSLContext.new
    assert_raises ArgumentError do
      context.ssl_version = "TLSv42" # ArgumentError: unknown SSL method `TLSv42'
    end
    assert_raises(TypeError) { context.ssl_version = 12 }
  end

  def test_context_minmax_version
    context = OpenSSL::SSL::SSLContext.new
    context.min_version = OpenSSL::SSL::TLS1_VERSION
    context.max_version = OpenSSL::SSL::TLS1_2_VERSION
    context.max_version = OpenSSL::SSL::TLS1_3_VERSION
  end if RUBY_VERSION > '2.3'

  def test_context_ciphers
    context = OpenSSL::SSL::SSLContext.new
    context.ciphers = "ALL"

    all_ciphers = context.ciphers.map { |cipher_array| cipher_array[0] }

    jce_installed = true # always assume installed (Java 8+)

    defunct_ciphers = [ # in terms of OpenSSL not reporting them on "ALL" (Ubuntu 16 LTS)
         jce_installed && "AECDH-AES256-SHA" && nil, # dropped in Java 11
         jce_installed && "ADH-AES256-SHA" && nil, # dropped in Java 11
         #"AECDH-DES-CBC3-SHA",
         #"ADH-DES-CBC3-SHA",
    ]

    shared_ciphers = [
        jce_installed && "ECDHE-ECDSA-AES256-SHA",
        jce_installed && "ECDHE-RSA-AES256-SHA",
        jce_installed && "AES256-SHA",
        jce_installed && "DHE-RSA-AES256-SHA",
        jce_installed && "DHE-DSS-AES256-SHA",
        "ECDHE-ECDSA-AES128-SHA",
        "ECDHE-RSA-AES128-SHA",
        "AES128-SHA",
        "DHE-RSA-AES128-SHA",
        "DHE-DSS-AES128-SHA",
        "AECDH-AES128-SHA" && nil, # dropped in Java 11
        "ADH-AES128-SHA" && nil, # dropped

        "ECDHE-RSA-AES128-SHA256", "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-SHA384", "ECDHE-RSA-AES256-GCM-SHA384",

        # added support in 0.10.3
        "ECDHE-ECDSA-AES256-SHA384",
        "ECDHE-RSA-AES256-SHA384",
        "DHE-RSA-AES256-SHA256",
        "DHE-DSS-AES256-SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384",
        "DHE-DSS-AES128-GCM-SHA256", "DHE-DSS-AES256-GCM-SHA384",
        "DHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES256-GCM-SHA384",
        "AES128-GCM-SHA256", "AES256-GCM-SHA384",

        # TLS 1.3
        'TLS_AES_256_GCM_SHA384'
    ]

    expected_ciphers = [
        #"ECDH-ECDSA-AES128-SHA256",
        #"ECDH-RSA-AES128-SHA256",
        #"ECDH-ECDSA-AES128-SHA",
        #"ECDH-RSA-AES128-SHA",
    ] + defunct_ciphers + shared_ciphers

    expected_ciphers.compact.each do |cipher|
      assert all_ciphers.include?(cipher), "#{cipher} should have been included"
    end

    diff = (expected_ciphers - all_ciphers).compact
    assert_equal [], diff
  end

  def test_set_ciphers_by_group_name
    context = OpenSSL::SSL::SSLContext.new
    context.ciphers = "AES"

    actual = context.ciphers.map { |cipher| cipher[0] }
    assert actual.include?("ECDHE-RSA-AES128-SHA")
    assert actual.include?("ECDHE-ECDSA-AES128-SHA")
    assert actual.include?("AES128-SHA")
  end

  def test_set_ciphers_by_cipher_name
    context = OpenSSL::SSL::SSLContext.new
    context.ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384"
    actual = context.ciphers.map { |cipher| cipher[0] }
    assert actual.include?("ECDHE-ECDSA-AES128-GCM-SHA256")
    assert actual.include?("ECDHE-ECDSA-AES256-GCM-SHA384")
  end

  def test_set_ciphers_by_array_of_names
    context = OpenSSL::SSL::SSLContext.new
    context.ciphers = ["ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384"]
    actual = context.ciphers.map { |cipher| cipher[0] }
    assert actual.include?("ECDHE-ECDSA-AES128-GCM-SHA256")
    assert actual.include?("ECDHE-ECDSA-AES256-GCM-SHA384")
  end

  def test_set_ciphers_by_array_of_name_version_bits
    context = OpenSSL::SSL::SSLContext.new
    context.ciphers = [["ECDHE-ECDSA-AES128-GCM-SHA256", "TLSv1.2", 128, 128]]
    actual = context.ciphers.map { |cipher| cipher[0] }
    assert actual.include?("ECDHE-ECDSA-AES128-GCM-SHA256")
  end

  def test_set_ciphers_by_array_supports_setting_java_names
    context = OpenSSL::SSL::SSLContext.new
    context.ciphers = [
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", # Java name
        "ECDHE-ECDSA-AES256-GCM-SHA384", # Ruby name
        'TLS_AES_256_GCM_SHA384' # same name in Ruby/Java
    ]
    actual = context.ciphers.map { |cipher| cipher[0] }
    assert actual.include?("ECDHE-ECDSA-AES128-GCM-SHA256"), actual.inspect
    assert actual.include?("ECDHE-ECDSA-AES256-GCM-SHA384"), actual.inspect
    assert actual.include?("TLS_AES_256_GCM_SHA384"), actual.inspect

    context.ciphers = [ 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' ]
    actual = context.ciphers.map { |cipher| cipher[0] }
    assert_equal actual, ['ECDHE-RSA-AES256-GCM-SHA384']
  end

  def test_set_ciphers_empty_array
    context = OpenSSL::SSL::SSLContext.new
    ex = assert_raise(OpenSSL::SSL::SSLError) do
      context.ciphers = []
    end
    # MRI: SSL_CTX_set_cipher_list: no cipher match
    assert_include ex.message, "no cipher match"
  end

  def test_invalid_ciphers_does_not_mutate_context
    context = OpenSSL::SSL::SSLContext.new
    ciphers = context.ciphers
    assert !ciphers.empty?
    begin
      context.ciphers = ['AES256-SHA123']
      fail 'raise expected'
    rescue OpenSSL::SSL::SSLError
    end
    assert_equal context.ciphers, ciphers
  end

end
