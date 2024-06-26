# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))
require File.expand_path('../ssl/test_helper', File.dirname(__FILE__))

class TestX509Store < TestCase

  def setup; require 'openssl'
    cert = File.read(File.expand_path('../newcert.pem', __FILE__)) # File.read(File.expand_path('../server.crt', __FILE__))
    @cert = OpenSSL::X509::Certificate.new(cert)
    @ca_cert = File.expand_path('../ca.crt', __FILE__) # File.expand_path('../demoCA/cacert.pem', __FILE__)
    @javastore = File.expand_path('../javastore.ts', __FILE__)
    @pem = File.expand_path('../Entrust.net_Premium_2048_Secure_Server_CA.pem', __FILE__) # validity: 1999 - 2029
  end

  @@ssl_cert_file = ENV['SSL_CERT_FILE']

  def teardown
    ENV['SSL_CERT_FILE'] = @@ssl_cert_file
  end

  def test_store_location_with_pem
    ENV['SSL_CERT_FILE'] = nil
    store = OpenSSL::X509::Store.new
    store.set_default_paths
    assert ! store.verify(@cert)

    ENV['SSL_CERT_FILE'] = @ca_cert
    store = OpenSSL::X509::Store.new
    assert ! store.verify(@cert)
    store.set_default_paths

    puts @cert.inspect if $VERBOSE
    #puts @cert.to_java java.security.cert.X509Certificate if $VERBOSE

    verified = store.verify(@cert)
    assert verified, "CA verification failed: #{store.inspect}"
  end

  def test_store_location_with_java_truststore
    skip unless defined? JRUBY_VERSION
    ENV['SSL_CERT_FILE'] = @javastore
    store = OpenSSL::X509::Store.new
    assert ! store.verify(@cert)
    store.set_default_paths

    #puts @cert.inspect if $VERBOSE
    #puts @cert.to_java java.security.cert.X509Certificate

    verified = store.verify(@cert)
    assert verified, "JKS verification failed: #{store.inspect}"
  end

  def test_use_gibberish_cert_file
    ENV['SSL_CERT_FILE'] = File.expand_path('../gibberish.pem', __FILE__)
    store = OpenSSL::X509::Store.new
    store.set_default_paths
    assert ! store.verify(@cert)
  end

  def test_use_default_cert_file_as_custom_file
    ENV['SSL_CERT_FILE'] = OpenSSL::X509::DEFAULT_CERT_FILE
    store = OpenSSL::X509::Store.new
    store.set_default_paths
    cert = OpenSSL::X509::Certificate.new(File.read(File.expand_path('../digicert.pem', __FILE__)))

    verified = store.verify(cert)
    assert verified, "digicert.pem verification failed: #{store.inspect}"
  end

  def test_add_file_to_store_with_custom_cert_file
    ENV['SSL_CERT_FILE'] = @ca_cert
    store = OpenSSL::X509::Store.new
    store.set_default_paths
    store.add_file @pem
    cert = OpenSSL::X509::Certificate.new(File.read(@pem))

    #p cert if $VERBOSE

    verified = store.verify(cert)
    assert verified, "verification failed for cert: #{cert.inspect} - #{store.inspect}"
  end


  def test_add_file_to_store_with_expired_ca_cert
    ENV['SSL_CERT_FILE'] = @ca_cert
    pem = File.expand_path('../Entrust.net_Secure_Server_CA.expired.pem', __FILE__)
    store = OpenSSL::X509::Store.new
    store.set_default_paths
    store.add_file pem
    cert = OpenSSL::X509::Certificate.new(File.read(pem))

    p cert if $VERBOSE

    verified = store.verify(cert)
    assert !verified, "verification passed for (expired) cert: #{cert.inspect}"
  end

  def test_use_non_existing_cert_file
    ENV['SSL_CERT_FILE'] = 'non-existing-file.crt'
    store = OpenSSL::X509::Store.new
    store.set_default_paths
    assert ! store.verify(@cert)
  end

  def test_verify_with_wrong_argument
    store = OpenSSL::X509::Store.new
    assert_raise(TypeError) { store.verify( 'not a cert object' ) }
  end

  def test_add_cert_concurrently
    store = OpenSSL::X509::Store.new
    t = []
    (0..25).each do
      t << Thread.new do
        (0..2).each do
          store.add_file @pem
        end
      end
    end

    t.each(&:join)
    # just ensure there is no concurreny error
    assert true
  end

  define_method 'test_add_same_cert_twice jruby/jruby-openssl#3' do
    root_key = OpenSSL::PKey::RSA.new 2048 # the CA's public/private key
    root_ca = OpenSSL::X509::Certificate.new
    root_ca.version = 2 # cf. RFC 5280 - to make it a "v3" certificate
    root_ca.serial = 1
    root_ca.subject = OpenSSL::X509::Name.parse "/DC=org/DC=ruby-lang/CN=Ruby CA"
    root_ca.issuer = root_ca.subject # root CA's are "self-signed"
    root_ca.public_key = root_key.public_key
    root_ca.not_before = Time.now
    root_ca.not_after = root_ca.not_before + 2 * 365 * 24 * 60 * 60 # 2 years validity
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = root_ca
    ef.issuer_certificate = root_ca
    root_ca.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true))
    root_ca.add_extension(ef.create_extension("keyUsage","keyCertSign, cRLSign", true))
    root_ca.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
    root_ca.add_extension(ef.create_extension("authorityKeyIdentifier","keyid:always",false))
    root_ca.sign(root_key, OpenSSL::Digest::SHA256.new)

    cert_store = OpenSSL::X509::Store.new
    assert cert_store.add_cert(root_ca) == cert_store
    # NOTE: logic reverted in JOSSL 0.11.0 to match C-OpenSSL (just adds certificates wout checks)
    #begin
      cert_store.add_cert(root_ca)
      #fail 'added same cert twice'
    #rescue OpenSSL::X509::StoreError => e
      #assert_equal 'cert already in hash table', e.message
    #end
  end

  def test_adding_pem_to_store_like_rubygems
    debug = false
    #OpenSSL.debug = true
    # mimic what rubygems/request#add_rubygems_trusted_certs does to find the .pem certificates
    # 1.7: jruby-complete-1.7.22.jar!/META-INF/jruby.home/lib/ruby/shared
    # 9.0: /opt/local/rvm/rubies/jruby-9.0.4.0/lib/ruby/stdlib
    base = $LOAD_PATH.detect { |p| p =~ /ruby\/shared/ || p =~ /ruby\/stdlib/ }
    raise "rubygems home not detected in $LOAD_PATH" unless base
    pems = Dir[ File.join(base, 'rubygems/ssl_certs/*pem') ]
    # assert_equal( 9, pems.size ) # >= 11 on 9K
    pems.each do |pem|
      puts pem.inspect if debug
      store = OpenSSL::X509::Store.new
      cert = OpenSSL::X509::Certificate.new(File.read(pem))
      assert ! store.verify(cert)
      store.add_file(pem)
      # only verify on self signed certifactes
      assert store.verify(cert) if pem !~ /COMODORSA|AddTrustExternalCARoot/
    end
  end if defined?(JRUBY_VERSION) && Gem::Version.create(JRUBY_VERSION) >= Gem::Version.create('9.1.17.0')

  def test_verify
    @rsa1024 = OpenSSL::PKey::RSA.new SSLTestHelper::TEST_KEY_RSA1 # OpenSSL::TestUtils::TEST_KEY_RSA1024
    @rsa2048 = OpenSSL::PKey::RSA.new SSLTestHelper::TEST_KEY_RSA2 # OpenSSL::TestUtils::TEST_KEY_RSA2048
    @dsa256  = OpenSSL::PKey::DSA.new SSLTestHelper::TEST_KEY_DSA256 # OpenSSL::TestUtils::TEST_KEY_DSA256
    @dsa512  = OpenSSL::PKey::DSA.new SSLTestHelper::TEST_KEY_DSA512 # OpenSSL::TestUtils::TEST_KEY_DSA512
    @ca1 = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=CA1")
    @ca2 = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=CA2")
    @ee1 = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=EE1")
    @ee2 = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=EE2")

    now = Time.at(Time.now.to_i)
    ca_exts = [
        ["basicConstraints","CA:TRUE",true],
        ["keyUsage","cRLSign,keyCertSign",true],
    ]
    ee_exts = [
        ["keyUsage","keyEncipherment,digitalSignature",true],
    ]
    ca1_cert = issue_cert(@ca1, @rsa2048, 1, ca_exts, nil, nil, not_before: now, not_after: now + 3600)
    ca2_cert = issue_cert(@ca2, @rsa1024, 2, ca_exts, ca1_cert, @rsa2048, not_before: now, not_after: now + 1800)
    ee1_cert = issue_cert(@ee1, @dsa256, 10, ee_exts, ca2_cert, @rsa1024, not_before: now, not_after: now + 1800)
    ee2_cert = issue_cert(@ee2, @dsa512, 20, ee_exts, ca2_cert, @rsa1024, not_before: now, not_after: now + 1800)
    ee3_cert = issue_cert(@ee2, @dsa512, 30, ee_exts, ca2_cert, @rsa1024, not_before: now - 100, not_after: now - 1)
    ee4_cert = issue_cert(@ee2, @dsa512, 40, ee_exts, ca2_cert, @rsa1024, not_before: now + 1000, not_after: now + 2000)

    revoke_info = []
    crl1   = issue_crl(revoke_info, 1, now, now+1800, [],
                       ca1_cert, @rsa2048, OpenSSL::Digest::SHA1.new)
    revoke_info = [ [2, now, 1], ]
    crl1_2 = issue_crl(revoke_info, 2, now, now+1800, [],
                       ca1_cert, @rsa2048, OpenSSL::Digest::SHA1.new)
    revoke_info = [ [20, now, 1], ]
    crl2   = issue_crl(revoke_info, 1, now, now+1800, [],
                       ca2_cert, @rsa1024, OpenSSL::Digest::SHA1.new)
    revoke_info = []
    crl2_2 = issue_crl(revoke_info, 2, now-100, now-1, [],
                       ca2_cert, @rsa1024, OpenSSL::Digest::SHA1.new)

    assert_equal(true, ca1_cert.verify(ca1_cert.public_key))   # self signed
    assert_equal(true, ca2_cert.verify(ca1_cert.public_key))   # issued by ca1
    assert_equal(true, ee1_cert.verify(ca2_cert.public_key))   # issued by ca2
    assert_equal(true, ee2_cert.verify(ca2_cert.public_key))   # issued by ca2
    assert_equal(true, ee3_cert.verify(ca2_cert.public_key))   # issued by ca2
    assert_equal(true, crl1.verify(ca1_cert.public_key))       # issued by ca1
    assert_equal(true, crl1_2.verify(ca1_cert.public_key))     # issued by ca1
    assert_equal(true, crl2.verify(ca2_cert.public_key))       # issued by ca2
    assert_equal(true, crl2_2.verify(ca2_cert.public_key))     # issued by ca2

    store = OpenSSL::X509::Store.new
    assert_equal(false, store.verify(ca1_cert))
    assert_not_equal(OpenSSL::X509::V_OK, store.error)

    assert_equal(false, store.verify(ca2_cert))
    assert_not_equal(OpenSSL::X509::V_OK, store.error)

    store.add_cert(ca1_cert)
    verify = store.verify(ca1_cert)
    # TODO only works when cert_self_signed is reduced to do a EXFLAG_SI instead of EXFLAG_SS
    assert_equal ["/DC=org/DC=ruby-lang/CN=CA1"],
                 store.chain.map { |cert| cert.subject.to_s }
    assert_equal(true, verify)

    verify = store.verify(ca2_cert)
    assert_equal ["/DC=org/DC=ruby-lang/CN=CA2", "/DC=org/DC=ruby-lang/CN=CA1"],
                 store.chain.map { |cert| cert.subject.to_s }
    assert_equal(true, verify)

    assert_equal(OpenSSL::X509::V_OK, store.error)
    assert_equal("ok", store.error_string)
    chain = store.chain
    assert_equal(2, chain.size)
    assert_equal(@ca2.to_der, chain[0].subject.to_der)
    assert_equal(@ca1.to_der, chain[1].subject.to_der)

    store.purpose = OpenSSL::X509::PURPOSE_SSL_CLIENT
    assert_equal(false, store.verify(ca2_cert))
    assert_not_equal(OpenSSL::X509::V_OK, store.error)

    store.purpose = OpenSSL::X509::PURPOSE_CRL_SIGN
    assert_equal(true, store.verify(ca2_cert))
    assert_equal(OpenSSL::X509::V_OK, store.error)

    store.add_cert(ca2_cert)
    store.purpose = OpenSSL::X509::PURPOSE_SSL_CLIENT
    assert_equal(true, store.verify(ee1_cert))
    assert_equal(true, store.verify(ee2_cert))
    assert_equal(OpenSSL::X509::V_OK, store.error)
    assert_equal("ok", store.error_string)
    chain = store.chain
    assert_equal(3, chain.size)
    assert_equal(@ee2.to_der, chain[0].subject.to_der)
    assert_equal(@ca2.to_der, chain[1].subject.to_der)
    assert_equal(@ca1.to_der, chain[2].subject.to_der)
    assert_equal(false, store.verify(ee3_cert))
    assert_equal(OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED, store.error)
    assert_match(/expire/i, store.error_string)
    assert_equal(false, store.verify(ee4_cert))
    assert_equal(OpenSSL::X509::V_ERR_CERT_NOT_YET_VALID, store.error)
    assert_match(/not yet valid/i, store.error_string)

    store = OpenSSL::X509::Store.new
    store.add_cert(ca1_cert)
    store.add_cert(ca2_cert)
    store.time = now + 1500
    assert_equal(true, store.verify(ca1_cert))
    assert_equal(true, store.verify(ca2_cert))
    assert_equal(true, store.verify(ee4_cert))
    store.time = now + 1900
    assert_equal(true, store.verify(ca1_cert))
    assert_equal(false, store.verify(ca2_cert))
    assert_equal(OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED, store.error)
    assert_equal(false, store.verify(ee4_cert))
    assert_equal(OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED, store.error)
    store.time = now + 4000
    assert_equal(false, store.verify(ee1_cert))
    assert_equal(OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED, store.error)
    assert_equal(false, store.verify(ee4_cert))
    assert_equal(OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED, store.error)

    # the underlying X509 struct caches the result of the last
    # verification for signature and not-before. so the following code
    # rebuilds new objects to avoid site effect.
    store.time = Time.now - 4000
    assert_equal(false, store.verify(OpenSSL::X509::Certificate.new(ca2_cert)))
    assert_equal(OpenSSL::X509::V_ERR_CERT_NOT_YET_VALID, store.error)
    assert_equal(false, store.verify(OpenSSL::X509::Certificate.new(ee1_cert)))
    assert_equal(OpenSSL::X509::V_ERR_CERT_NOT_YET_VALID, store.error)

    return unless defined?(OpenSSL::X509::V_FLAG_CRL_CHECK)

    store = OpenSSL::X509::Store.new
    store.purpose = OpenSSL::X509::PURPOSE_ANY
    store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK
    store.add_cert(ca1_cert)
    store.add_crl(crl1)   # revoke no cert
    store.add_crl(crl2)   # revoke ee2_cert
    assert_equal(true,  store.verify(ca1_cert))
    assert_equal ["/DC=org/DC=ruby-lang/CN=CA1"],
                 store.chain.map { |cert| cert.subject.to_s }

    assert_equal(true,  store.verify(ca2_cert))
    assert_equal ["/DC=org/DC=ruby-lang/CN=CA2", "/DC=org/DC=ruby-lang/CN=CA1"],
                 store.chain.map { |cert| cert.subject.to_s }

    verify = store.verify(ee1_cert, [ca2_cert])
    assert_equal(true,  verify)

    verify = store.verify(ee2_cert, [ca2_cert])
    assert_equal(false, verify)

    store = OpenSSL::X509::Store.new
    store.purpose = OpenSSL::X509::PURPOSE_ANY
    store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK
    store.add_cert(ca1_cert)
    store.add_crl(crl1_2) # revoke ca2_cert
    store.add_crl(crl2)   # revoke ee2_cert

    verify = store.verify(ca1_cert)
    assert_equal ["/DC=org/DC=ruby-lang/CN=CA1"],
                 store.chain.map { |cert| cert.subject.to_s }
    assert_equal(true, verify)

    verify = store.verify(ca2_cert)
    assert_equal ["/DC=org/DC=ruby-lang/CN=CA2", "/DC=org/DC=ruby-lang/CN=CA1"],
                 store.chain.map { |cert| cert.subject.to_s }
    assert_equal(false, verify)

    assert_equal(true,  store.verify(ee1_cert, [ca2_cert]),
                 "This test is expected to be success with OpenSSL 0.9.7c or later.")
    assert_equal(false, store.verify(ee2_cert, [ca2_cert]))

    store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK | OpenSSL::X509::V_FLAG_CRL_CHECK_ALL

    verify = store.verify(ca1_cert)
    assert_equal ["/DC=org/DC=ruby-lang/CN=CA1"],
                 store.chain.map { |cert| cert.subject.to_s }
    puts "verify(ca1_cert) #{verify} - store.error: #{store.error} (#{store.error_string})"
    assert_equal(true,  verify)

    assert_equal(false, store.verify(ca2_cert))
    assert_equal(false, store.verify(ee1_cert, [ca2_cert]))
    assert_equal(false, store.verify(ee2_cert, [ca2_cert]))

    store = OpenSSL::X509::Store.new
    store.purpose = OpenSSL::X509::PURPOSE_ANY
    store.flags =
        OpenSSL::X509::V_FLAG_CRL_CHECK|OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
    store.add_cert(ca1_cert)
    store.add_cert(ca2_cert)
    store.add_crl(crl1)
    store.add_crl(crl2_2) # issued by ca2 but expired.
    assert_equal(true, store.verify(ca1_cert))
    assert_equal(true, store.verify(ca2_cert))
    assert_equal(false, store.verify(ee1_cert))
    assert_equal(OpenSSL::X509::V_ERR_CRL_HAS_EXPIRED, store.error)
    assert_equal(false, store.verify(ee2_cert))
  end

  def test_verify_same_subject_ca

    puts JOpenSSL::VERSION if defined? JRUBY_VERSION

    @rsa1 = OpenSSL::PKey::RSA.generate 2048
    @rsa2 = OpenSSL::PKey::RSA.generate 2048
    @rsa3 = OpenSSL::PKey::RSA.generate 2048
    @rsa4 = OpenSSL::PKey::RSA.generate 2048
    @dsa1 = OpenSSL::PKey::DSA.generate 512
    @dsa2 = OpenSSL::PKey::DSA.generate 512
    @ca_same = OpenSSL::X509::Name.parse("/DC=com/DC=same-name/CN=CA")
    @ca_other = OpenSSL::X509::Name.parse("/DC=co/DC=anotherOne/CN=CA")
    @ee1 = OpenSSL::X509::Name.parse("/DC=com/DC=example/CN=ServerCert1")
    @ee2 = OpenSSL::X509::Name.parse("/DC=com/DC=example/CN=ServerCert2")
    @ee4 = OpenSSL::X509::Name.parse("/DC=com/DC=example/CN=ServerCert4")

    now = Time.at(Time.now.to_i)
    not_before = now - 365 * 24 * 60 * 60
    not_after = now + 24 * 60 * 60
    ca_exts1 = [
        ["basicConstraints","CA:TRUE",true],
        ["keyUsage","cRLSign,keyCertSign",true],
    ]
    ca_exts2 = [
        ["basicConstraints","CA:TRUE",true],
        ["keyUsage","keyCertSign",true],
    ]
    ee_exts = [
        ["keyUsage","keyEncipherment,digitalSignature",true],
    ]
    ca1_cert = issue_cert(@ca_same, @rsa1, 1, ca_exts1, nil, nil, not_before: not_before, not_after: now - 60 * 60)
    ca2_cert = issue_cert(@ca_same, @rsa2, 2, ca_exts2, nil, nil, not_before: not_before, not_after: not_after)
    ca3_cert = issue_cert(@ca_other, @rsa3, 3, ca_exts1, nil, nil, not_before: not_before, not_after: not_after)
    ca4_cert = issue_cert(@ca_same, @rsa4, 4, ca_exts1, nil, nil, not_before: not_before, not_after: not_after)
    ee1_cert = issue_cert(@ee1, @dsa1, 10, ee_exts, ca1_cert, @rsa1, not_before: now - 60, not_after: now + 1800)
    ee2_cert = issue_cert(@ee2, @dsa2, 20, ee_exts, ca2_cert, @rsa2, not_before: now - 60, not_after: now + 1800)
    ee4_cert = issue_cert(@ee4, @dsa2, 20, ee_exts, ca4_cert, @rsa4, not_before: now - 60, not_after: now + 1800)

    cert_store = OpenSSL::X509::Store.new
    cert_store.add_cert ca1_cert
    cert_store.add_cert ca2_cert
    cert_store.add_cert ca3_cert
    cert_store.add_cert ca4_cert

    ok = cert_store.verify(ee1_cert)
    assert_equal 'certificate signature failure', cert_store.error_string
    assert_equal false, ok

    ok = cert_store.verify(ee2_cert)
    assert_equal 'ok', cert_store.error_string
    assert_equal true, ok

    ok = cert_store.verify(ee4_cert)
    assert_equal 'certificate signature failure', cert_store.error_string
    assert_equal false, ok # OpenSSL 1.1.1 behavior
  end

end
