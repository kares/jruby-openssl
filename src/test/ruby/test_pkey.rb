# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestPKey < TestCase

  KEY = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArTlm5TxJp3WHMNmWIfo/\nWvkyhJCXc1S78Y9B8lSXxXnkRqX8Twxu5EkdUP0TwgD5gp0TGy7UPm/SgWlQOcqX\nqtdOWq/Hk29Ve9z6k6wTmst7NTefmm/7OqkeYmBhfhoECLCKBADM8ctjoqD63R0e\n3bUW2knq6vCS5YMmD76/5UoU647BzB9CjgDzjuTKEbXL5AvcO5wWDgHSp7CA+2t4\nIFQvQMrPso5mvm2hNvD19vI0VjiY21rKgkJQAXSrLgkJg/fTL2wQiz10d2GnYsmx\nDeJCiBMwC+cmRW2eWePqaCPaWJwr92KsIiry+LgyGb3y01SUVV8kQgQXazutHqfu\ncQIDAQAB\n-----END PUBLIC KEY-----\n"

  def test_pkey_read
    pkey = OpenSSL::PKey.read(KEY)
    assert_same OpenSSL::PKey::RSA, pkey.class
    assert_true pkey.public?
    assert_false pkey.private?
    assert_equal OpenSSL::PKey::RSA.new(KEY).n, pkey.n
    assert_equal OpenSSL::PKey::RSA.new(KEY).e, pkey.e
  end

  def test_read_files
    custom_fixtures_path = File.expand_path('fixtures/pkey/custom', File.dirname(__FILE__))

    key = OpenSSL::PKey.read(File.read(File.join(custom_fixtures_path, 'ec256-private-v2.pem')))
    assert_equal OpenSSL::PKey::EC, key.class
    assert key.private_key?

    key = OpenSSL::PKey.read(File.read(File.join(custom_fixtures_path, 'ec256k-private.pem')))
    assert_equal OpenSSL::PKey::EC, key.class
    assert key.private_key?
    assert_equal 'secp256k1', key.group.curve_name

    key = OpenSSL::PKey.read(File.read(File.join(custom_fixtures_path, 'ec256k-public.pem')))
    assert_equal OpenSSL::PKey::EC, key.class
    assert key.public_key?

    key = OpenSSL::PKey.read(File.read(File.join(custom_fixtures_path, 'ec256-public-v2.pem')))
    assert_equal OpenSSL::PKey::EC, key.class
    assert key.public_key?
    assert_equal 'prime256v1', key.group.curve_name

    key = OpenSSL::PKey.read(File.read(File.join(custom_fixtures_path, 'ec512-private.pem')))
    assert_equal OpenSSL::PKey::EC, key.class
    assert key.private_key?
    assert_equal 'secp521r1', key.group.curve_name

    key = OpenSSL::PKey.read(File.read(File.join(custom_fixtures_path, 'ec512-public.pem')))
    assert_equal OpenSSL::PKey::EC, key.class
    assert key.public_key?
    assert_equal 'secp521r1', key.group.curve_name

    key = OpenSSL::PKey.read(File.read(File.join(custom_fixtures_path, 'rsa-2048-private.pem')))
    assert_equal OpenSSL::PKey::RSA, key.class
    assert key.private?
    key = OpenSSL::PKey.read(File.read(File.join(custom_fixtures_path, 'rsa-2048-public.pem')))
    assert_equal OpenSSL::PKey::RSA, key.class
    assert key.public?
  end

  def test_pkey_read_pkcs8_and_check_with_cert
    pkey = File.expand_path('pkey-pkcs8.pem', File.dirname(__FILE__))
    pkey = OpenSSL::PKey.read(File.read(pkey), nil)

    assert_true pkey.private?
    assert_true pkey.public?
    assert pkey.public_key.to_s

    cert = File.expand_path('pkey-cert.pem', File.dirname(__FILE__))
    cert = OpenSSL::X509::Certificate.new(File.read(cert))

    assert_true cert.check_private_key(pkey)
  end

  def test_pkey_pem_file_error
    begin
      ret = OpenSSL::PKey.read('not a PEM file')
      fail "expected OpenSSL::PKey.read to raise (got: #{ret.inspect})"
    rescue OpenSSL::PKey::PKeyError => e
      assert_equal 'Could not parse PKey: unsupported', e.message
    end

    begin
      ret = OpenSSL::PKey::RSA.new('not a PEM file')
      fail "expected OpenSSL::PKey::RSA.new to raise (got: #{ret.inspect})"
    rescue OpenSSL::PKey::PKeyError
      assert true
    end
  end

  def test_pkey_dh
    dh = OpenSSL::PKey::DH.new
    assert_equal nil, dh.p
    assert_equal nil, dh.priv_key

    # OpenSSL::PKey::PKeyError: dh#set_pqg= is incompatible with OpenSSL 3.0
    if defined? JRUBY_VERSION
      dh.set_pqg(1_000_000, nil, 10)
      assert_equal 1_000_000, dh.p
      assert_equal 10, dh.g
    end
    assert_equal nil, dh.q
  end

  def test_hmac_sign_verify
    pkey = OpenSSL::PKey.generate_key("HMAC", { "key" => "abcd" })

    assert_instance_of OpenSSL::PKey::PKey, pkey
    assert_equal "HMAC", pkey.oid
    assert_equal false, pkey.public?
    assert_equal true, pkey.private?
    assert_equal "abcd", pkey.raw_private_key

    hmac = OpenSSL::HMAC.new("abcd", "SHA256").update("data").digest
    assert_equal hmac, pkey.sign("SHA256", "data")
    assert_match(/HMAC Private-Key/, pkey.to_text)

    assert_raise(OpenSSL::PKey::PKeyError) { pkey.verify("SHA256", hmac, "data") }
    assert_raise(OpenSSL::PKey::PKeyError) { pkey.raw_public_key }
  end

  def test_hmac_new_raw_private_key
    pkey = OpenSSL::PKey.new_raw_private_key("HMAC", "secret")

    assert_instance_of OpenSSL::PKey::PKey, pkey
    assert_equal "secret", pkey.raw_private_key
    assert_equal OpenSSL::HMAC.digest("SHA256", "secret", "payload"), pkey.sign("SHA256", "payload")
  end

  def test_hmac_generate_key_requires_key_option
    assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.generate_key("HMAC") }
    assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.generate_key("HMAC", {}) }
  end

  def test_generate_key_from_ec_params
    ec_params = OpenSSL::PKey::EC.new("secp384r1")

    pkey = OpenSSL::PKey.generate_key(ec_params)

    assert_instance_of OpenSSL::PKey::EC, pkey
    assert_equal "secp384r1", pkey.group.curve_name
    assert_not_nil pkey.private_key
    assert_not_nil pkey.public_key
    assert_nil ec_params.private_key
  end

  def test_generate_key_from_dsa_params
    original = Fixtures.pkey("dsa1024")
    dsa_params = OpenSSL::PKey::DSA.new
    dsa_params.set_pqg(original.p, original.q, original.g)

    pkey = OpenSSL::PKey.generate_key(dsa_params)

    assert_instance_of OpenSSL::PKey::DSA, pkey
    assert_equal original.p, pkey.p
    assert_equal original.q, pkey.q
    assert_equal original.g, pkey.g
    assert_not_nil pkey.priv_key
    assert_not_nil pkey.pub_key
    assert_nil dsa_params.priv_key
    assert_nil dsa_params.pub_key
  end

  def test_generate_parameters_ec
    pkey = OpenSSL::PKey.generate_parameters("EC", {
      "ec_paramgen_curve" => "secp384r1"
    })

    assert_instance_of OpenSSL::PKey::EC, pkey
    assert_equal "secp384r1", pkey.group.curve_name
    assert_equal nil, pkey.private_key
  end

  def test_generate_parameters_ec_invalid_option
    assert_raise(OpenSSL::PKey::PKeyError) do
      OpenSSL::PKey.generate_parameters("EC", "invalid" => "option")
    end
  end

  def test_generate_parameters_dsa
    pkey = OpenSSL::PKey.generate_parameters("DSA", {
      "dsa_paramgen_bits" => 1024
    })

    assert_instance_of OpenSSL::PKey::DSA, pkey
    assert_equal 1024, pkey.p.num_bits
    assert_not_nil pkey.p
    assert_not_nil pkey.q
    assert_not_nil pkey.g
    assert_nil pkey.priv_key
    assert_nil pkey.pub_key
  end

  def test_generate_parameters_dh
    pkey = OpenSSL::PKey.generate_parameters("DH", {
      "dh_paramgen_prime_len" => 512,
      "dh_paramgen_generator" => 5
    })

    assert_instance_of OpenSSL::PKey::DH, pkey
    assert_equal 512, pkey.p.num_bits
    assert_equal 5, pkey.g.to_i
    assert_nil pkey.priv_key
    assert_nil pkey.pub_key
  end

  def test_generate_key_rsa_with_options
    pkey = OpenSSL::PKey.generate_key("RSA", {
      "rsa_keygen_bits" => 1024,
      "rsa_keygen_pubexp" => 3
    })

    assert_instance_of OpenSSL::PKey::RSA, pkey
    assert_equal 1024, pkey.n.num_bits
    assert_equal 3, pkey.e.to_i
    assert pkey.private?
  end

  def test_generate_key_ec_with_options
    pkey = OpenSSL::PKey.generate_key("EC", {
      "ec_paramgen_curve" => "secp384r1"
    })

    assert_instance_of OpenSSL::PKey::EC, pkey
    assert_equal "secp384r1", pkey.group.curve_name
    assert_not_nil pkey.private_key
  end

  def test_generate_key_dh_with_options
    pkey = OpenSSL::PKey.generate_key("DH", {
      "dh_paramgen_prime_len" => 512,
      "dh_paramgen_generator" => 5
    })

    assert_instance_of OpenSSL::PKey::DH, pkey
    assert_equal 512, pkey.p.num_bits
    assert_equal 5, pkey.g.to_i
    assert_not_nil pkey.pub_key
    assert_not_nil pkey.priv_key
  end

  def test_generate_key_dsa_requires_parameters
    assert_raise(OpenSSL::PKey::PKeyError) do
      OpenSSL::PKey.generate_key("DSA")
    end
  end

  def test_generate_key_dsa_with_options
    pkey = OpenSSL::PKey.generate_key("DSA", {
      "dsa_paramgen_bits" => 1024
    })

    assert_instance_of OpenSSL::PKey::DSA, pkey
    assert_equal 1024, pkey.p.num_bits
    assert_not_nil pkey.pub_key
    assert_not_nil pkey.priv_key
  end

  def test_raw_initialize_errors
    assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.new_raw_private_key("foo123", "xxx") }
    assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.new_raw_private_key("ED25519", "xxx") }
    assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.new_raw_public_key("foo123", "xxx") }
    assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.new_raw_public_key("ED25519", "xxx") }
  end

  def test_oid_and_inspect
    rsa = Fixtures.pkey("rsa-1.pem")
    assert_equal "rsaEncryption", rsa.oid
    assert_match(/OpenSSL::PKey::RSA/, rsa.inspect)
  end

  def test_read_pem_skip_non_key_blocks
    orig = Fixtures.pkey("rsa-1.pem")
    subject = OpenSSL::X509::Name.new([["CN", "test"]])
    cert = issue_cert(subject, orig, 1, [], nil, nil)

    input = cert.to_text + cert.to_pem + orig.to_text + orig.private_to_pem
    pkey = OpenSSL::PKey.read(input)
    assert_equal orig.private_to_der, pkey.private_to_der
  end

  def test_compare?
    key1 = Fixtures.pkey("rsa-1.pem")
    key2 = Fixtures.pkey("rsa-1.pem")
    key3 = Fixtures.pkey("rsa-2.pem")
    key4 = Fixtures.pkey("p256")

    assert_equal(true, key1.compare?(key2))
    assert_equal(true, key1.public_key.compare?(key2))
    assert_equal(true, key2.compare?(key1))
    assert_equal(true, key2.public_key.compare?(key1))

    assert_equal(false, key1.compare?(key3))

    assert_raise(TypeError) do
      key1.compare?(key4)
    end
  end

  def test_compare_with_certificate_public_key
    fixtures = File.dirname(__FILE__)
    cert = OpenSSL::X509::Certificate.new(File.read(File.join(fixtures, 'pkey-cert.pem')))
    matching_key = OpenSSL::PKey.read(File.read(File.join(fixtures, 'pkey-pkcs8.pem')))
    other_key    = Fixtures.pkey("rsa-1.pem")

    assert_equal true,  matching_key.compare?(cert.public_key)
    assert_equal false, other_key.compare?(cert.public_key)
  end

  def test_to_java
    pkey = OpenSSL::PKey.read(KEY)
    assert_kind_of java.security.PublicKey, pkey.to_java
    assert_kind_of java.security.PublicKey, pkey.to_java(java.security.PublicKey)
    assert_kind_of java.security.PublicKey, pkey.to_java(java.security.interfaces.RSAPublicKey)
    assert_kind_of java.security.PublicKey, pkey.to_java(java.security.Key)
    pub_key = pkey.to_java(java.security.PublicKey)
    if pub_key.is_a? org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey
      assert_kind_of java.security.PublicKey, pkey.to_java(org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey)
    end
    assert_raise_kind_of(TypeError) { pkey.to_java(java.security.interfaces.ECPublicKey) }
    # NOTE: won't fail as it's a marker that is neither a PublicKey or PrivateKey (also does not sub-class Key)
    #assert_raise_kind_of(TypeError) { pkey.to_java(java.security.interfaces.ECKey) }
  end if defined?(JRUBY_VERSION)

end
