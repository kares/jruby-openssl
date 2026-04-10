require File.expand_path('test_helper', File.dirname(__FILE__))

class TestNSSPKI < TestCase
  # from the Netscape SPKI specification
  B64 = 'MIHFMHEwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAnX0TILJrOMUue+PtwBRE6XfV' \
        'WtKQbsshxk5ZhcUwcwyvcnIq9b82QhJdoACdD34rqfCAIND46fXKQUnb0mvKzQID' \
        'AQABFhFNb3ppbGxhSXNNeUZyaWVuZDANBgkqhkiG9w0BAQQFAANBAAKv2Eex2n/S' \
        'r/7iJNroWlSzSMtTiQTEB+ADWHGj9u1xrUrOilq/o2cuQxIfZcNZkYAkWP4DubqW' \
        'i0//rgBvmco='

  def test_decode_data
    spki = OpenSSL::Netscape::SPKI.new(B64)
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
    # signature hex bytes with : separators
    assert_match(/[0-9a-f]{2}(:[0-9a-f]{2})+/, text)
  end
end
