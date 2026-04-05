# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestPKeyEdDSA < TestCase

  # RFC 8032 Section 7.1 TEST 2
  PRIV_PEM = <<~EOF
  -----BEGIN PRIVATE KEY-----
  MC4CAQAwBQYDK2VwBCIEIEzNCJso/5banbbDRuwRTg9bijGfNaumJNqM9u1PuKb7
  -----END PRIVATE KEY-----
  EOF

  PUB_PEM = <<~EOF
  -----BEGIN PUBLIC KEY-----
  MCowBQYDK2VwAyEAPUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=
  -----END PUBLIC KEY-----
  EOF

  def test_read_public_key
    pub = OpenSSL::PKey.read(PUB_PEM)
    assert_instance_of OpenSSL::PKey::PKey, pub
    assert_equal 'ED25519', pub.oid
  end

  def test_read_private_key
    priv = OpenSSL::PKey.read(PRIV_PEM)
    assert_instance_of OpenSSL::PKey::PKey, priv
    assert_equal 'ED25519', priv.oid
  end

  def test_pem_round_trip
    priv = OpenSSL::PKey.read(PRIV_PEM)
    pub = OpenSSL::PKey.read(PUB_PEM)
    assert_equal PRIV_PEM, priv.private_to_pem
    assert_equal PUB_PEM, priv.public_to_pem
    assert_equal PUB_PEM, pub.public_to_pem
  end

  def test_raw_private_key
    priv = OpenSSL::PKey.read(PRIV_PEM)
    assert_equal '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
      priv.raw_private_key.unpack1('H*')
  end

  def test_raw_public_key
    priv = OpenSSL::PKey.read(PRIV_PEM)
    assert_equal '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
      priv.raw_public_key.unpack1('H*')
  end

  def test_new_raw_private_key_round_trip
    priv = OpenSSL::PKey.read(PRIV_PEM)
    priv2 = OpenSSL::PKey.new_raw_private_key('ED25519', priv.raw_private_key)
    assert_equal priv.private_to_pem, priv2.private_to_pem
  end

  def test_new_raw_public_key_round_trip
    priv = OpenSSL::PKey.read(PRIV_PEM)
    pub = OpenSSL::PKey.read(PUB_PEM)
    pub2 = OpenSSL::PKey.new_raw_public_key('ED25519', priv.raw_public_key)
    assert_equal pub.public_to_pem, pub2.public_to_pem
  end

  def test_sign_and_verify_rfc8032
    priv = OpenSSL::PKey.read(PRIV_PEM)
    pub = OpenSSL::PKey.read(PUB_PEM)

    sig = [<<~EOF.gsub(/[^0-9a-f]/, '')].pack('H*')
    92a009a9f0d4cab8720e820b5f642540
    a2b27b5416503f8fb3762223ebdb69da
    085ac1e43e15996e458f3613d0f11d8c
    387b2eaeb4302aeeb00d291612bb0c00
    EOF
    data = ['72'].pack('H*')

    assert_equal sig, priv.sign(nil, data)
    assert_equal true, priv.verify(nil, sig, data)
    assert_equal true, pub.verify(nil, sig, data)
    assert_equal false, pub.verify(nil, sig, data.succ)
  end

  def test_sign_rejects_digest
    priv = OpenSSL::PKey.read(PRIV_PEM)
    assert_raise(OpenSSL::PKey::PKeyError) { priv.sign('SHA512', 'data') }
  end

  def test_verify_rejects_digest
    priv = OpenSSL::PKey.read(PRIV_PEM)
    pub = OpenSSL::PKey.read(PUB_PEM)
    sig = priv.sign(nil, 'data')
    assert_raise(OpenSSL::PKey::PKeyError) { pub.verify('SHA512', sig, 'data') }
  end

  def test_derive_raises
    priv = OpenSSL::PKey.read(PRIV_PEM)
    pub = OpenSSL::PKey.read(PUB_PEM)
    assert_raise(OpenSSL::PKey::PKeyError) { priv.derive(pub) }
  end

  def test_generate_key
    key = OpenSSL::PKey.generate_key('ED25519')
    assert_instance_of OpenSSL::PKey::PKey, key
    assert_equal 'ED25519', key.oid
    assert_not_nil key.raw_private_key
    assert_not_nil key.raw_public_key

    # Can sign and verify
    sig = key.sign(nil, 'hello')
    assert_equal true, key.verify(nil, sig, 'hello')
  end

  def test_new_raw_private_key_rejects_bad_data
    assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.new_raw_private_key('ED25519', 'xxx') }
  end

  def test_new_raw_public_key_rejects_bad_data
    assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.new_raw_public_key('ED25519', 'xxx') }
  end
end
