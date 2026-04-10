require File.expand_path('test_helper', File.dirname(__FILE__))

class TestNSSPKI < TestCase
  # from the Netscape SPKI specification
  B64 = 'MIHFMHEwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAnX0TILJrOMUue+PtwBRE6XfV' \
        'WtKQbsshxk5ZhcUwcwyvcnIq9b82QhJdoACdD34rqfCAIND46fXKQUnb0mvKzQID' \
        'AQABFhFNb3ppbGxhSXNNeUZyaWVuZDANBgkqhkiG9w0BAQQFAANBAAKv2Eex2n/S' \
        'r/7iJNroWlSzSMtTiQTEB+ADWHGj9u1xrUrOilq/o2cuQxIfZcNZkYAkWP4DubqW' \
        'i0//rgBvmco='

  def test_build_data
    key1 = Fixtures.pkey('rsa1024')
    key2 = Fixtures.pkey('rsa2048')
    spki = OpenSSL::Netscape::SPKI.new
    spki.challenge = 'RandomChallenge'
    spki.public_key = key1
    spki.sign(key1, OpenSSL::Digest.new('SHA256'))
    assert spki.verify(key1)
    assert !spki.verify(key2)
    assert_not_nil spki.to_text
    assert_not_nil spki.to_der
  end

  def test_decode_data
    spki = OpenSSL::Netscape::SPKI.new(B64)
    assert_equal 'MozillaIsMyFriend', spki.challenge
    assert_instance_of OpenSSL::PKey::RSA, spki.public_key

    # also accepts DER input
    spki = OpenSSL::Netscape::SPKI.new(B64.unpack1('m'))
    assert_equal 'MozillaIsMyFriend', spki.challenge
    assert_instance_of OpenSSL::PKey::RSA, spki.public_key
  end

  def test_to_text
    spki = OpenSSL::Netscape::SPKI.new(B64)
    text = spki.to_text

    assert_not_nil text, 'to_text should not return nil'
    assert_match(/\ANetscape SPKI:\n/, text)
    assert_match(/Public Key Algorithm: /, text)
    assert_match(/Challenge String: MozillaIsMyFriend/, text)
    assert_match(/Signature Algorithm: /, text)
    assert_match(/[0-9a-f]{2}(:[0-9a-f]{2})+/, text)
  end

  def test_to_text_after_sign
    key = Fixtures.pkey('rsa1024')
    spki = OpenSSL::Netscape::SPKI.new
    spki.challenge = 'MyChallenge'
    spki.public_key = key
    spki.sign(key, OpenSSL::Digest.new('SHA256'))

    text = spki.to_text
    assert_match(/\ANetscape SPKI:\n/, text)
    assert_match(/Challenge String: MyChallenge/, text)
    assert_match(/Signature Algorithm: /, text)
    assert_match(/[0-9a-f]{2}(:[0-9a-f]{2})+/, text)
  end
end
