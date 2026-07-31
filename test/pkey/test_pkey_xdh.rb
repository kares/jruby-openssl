# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestPKeyXDH < TestCase

  # RFC 7748 Section 6.1
  ALICE_PEM = <<~EOF
  -----BEGIN PRIVATE KEY-----
  MC4CAQAwBQYDK2VuBCIEIHcHbQpzGKV9PBbBclGyZkXfTC+H68CZKrF3+6UduSwq
  -----END PRIVATE KEY-----
  EOF

  BOB_PEM = <<~EOF
  -----BEGIN PUBLIC KEY-----
  MCowBQYDK2VuAyEA3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=
  -----END PUBLIC KEY-----
  EOF

  SHARED_SECRET = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'

  def setup
    super
    omit_on_fips 'X25519/X448 are not FIPS-approved'
  end

  def test_read_private_key
    priv = OpenSSL::PKey.read(ALICE_PEM)
    assert_instance_of OpenSSL::PKey::PKey, priv
    assert_equal 'X25519', priv.oid
  end

  def test_read_public_key
    pub = OpenSSL::PKey.read(BOB_PEM)
    assert_instance_of OpenSSL::PKey::PKey, pub
    assert_equal 'X25519', pub.oid
  end

  def test_pem_round_trip
    priv = OpenSSL::PKey.read(ALICE_PEM)
    pub = OpenSSL::PKey.read(BOB_PEM)
    assert_equal ALICE_PEM, priv.private_to_pem
    assert_equal BOB_PEM, pub.public_to_pem
  end

  def test_raw_keys
    priv = OpenSSL::PKey.read(ALICE_PEM)
    pub = OpenSSL::PKey.read(BOB_PEM)
    assert_equal '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
                 priv.raw_private_key.unpack1('H*')
    assert_equal 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
                 pub.raw_public_key.unpack1('H*')
  end

  def test_new_raw_key_round_trip
    priv = OpenSSL::PKey.read(ALICE_PEM)
    pub = OpenSSL::PKey.read(BOB_PEM)
    assert_equal priv.private_to_pem,
                 OpenSSL::PKey.new_raw_private_key('X25519', priv.raw_private_key).private_to_pem
    assert_equal pub.public_to_pem,
                 OpenSSL::PKey.new_raw_public_key('X25519', pub.raw_public_key).public_to_pem
  end

  def test_derive_rfc7748
    priv = OpenSSL::PKey.read(ALICE_PEM)
    pub = OpenSSL::PKey.read(BOB_PEM)
    assert_equal [SHARED_SECRET].pack('H*'), priv.derive(pub)
  end

  def test_derive_without_private_key
    pub = OpenSSL::PKey.read(BOB_PEM)
    assert_raise(OpenSSL::PKey::PKeyError) { pub.derive(pub) }
  end

  def test_sign_not_supported
    priv = OpenSSL::PKey.read(ALICE_PEM)
    assert_raise(OpenSSL::PKey::PKeyError) { priv.sign(nil, 'data') }
  end

  def test_generate_key
    key = OpenSSL::PKey.generate_key('X25519')
    assert_instance_of OpenSSL::PKey::PKey, key
    assert_equal 'X25519', key.oid
    assert_equal 32, key.raw_private_key.bytesize
    assert_equal 32, key.raw_public_key.bytesize
  end

  def test_generate_key_x448
    key = OpenSSL::PKey.generate_key('X448')
    assert_equal 'X448', key.oid
    assert_equal 56, key.raw_private_key.bytesize
    assert_equal 56, key.raw_public_key.bytesize
  end

  def test_derive_x448_round_trip
    alice = OpenSSL::PKey.generate_key('X448')
    bob = OpenSSL::PKey.generate_key('X448')
    assert_equal alice.derive(bob), bob.derive(alice)
    assert_equal 56, alice.derive(bob).bytesize
  end

  def test_x448_pem_round_trip
    key = OpenSSL::PKey.generate_key('X448')
    assert_equal 'X448', OpenSSL::PKey.read(key.private_to_pem).oid
    assert_equal 'X448', OpenSSL::PKey.read(key.public_to_pem).oid
  end

  def test_new_raw_key_rejects_bad_data
    assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.new_raw_private_key('X25519', 'xxx') }
    assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.new_raw_public_key('X25519', 'xxx') }
  end

  def test_to_text
    priv = OpenSSL::PKey.read(ALICE_PEM)
    assert_match(/\AX25519 Private-Key:/, priv.to_text)
  end
end
