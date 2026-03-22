# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestPKCS12 < TestCase

  def setup
    super

    @key = OpenSSL::PKey::RSA.new(2048)
    @cert = issue_cert
  end

  def test_create_and_parse_with_password
    p12 = OpenSSL::PKCS12.create("secret", "myalias", @key, @cert)
    assert p12.to_der.bytesize > 0

    parsed = OpenSSL::PKCS12.new(p12.to_der, "secret")
    assert_instance_of OpenSSL::PKey::RSA, parsed.key
    assert_equal @cert.subject.to_s, parsed.certificate.subject.to_s
  end

  def test_create_and_parse_with_empty_password
    p12 = OpenSSL::PKCS12.create("", "myalias", @key, @cert)
    parsed = OpenSSL::PKCS12.new(p12.to_der, "")
    assert_instance_of OpenSSL::PKey::RSA, parsed.key
    assert_equal @cert.subject.to_s, parsed.certificate.subject.to_s
  end

  def test_create_and_parse_with_nil_password
    p12 = OpenSSL::PKCS12.create(nil, "myalias", @key, @cert)
    parsed = OpenSSL::PKCS12.new(p12.to_der)
    assert_instance_of OpenSSL::PKey::RSA, parsed.key
    assert_equal @cert.subject.to_s, parsed.certificate.subject.to_s
  end

  def test_parse_with_wrong_password_raises
    p12 = OpenSSL::PKCS12.create("right", "myalias", @key, @cert)
    assert_raise(OpenSSL::PKCS12::PKCS12Error) do
      OpenSSL::PKCS12.new(p12.to_der, "wrong")
    end
  end

  def test_create_and_parse_with_ca_certs
    ca_key = OpenSSL::PKey::RSA.new(2048)
    ca_cert = issue_cert(cn: "CA", key: ca_key)
    leaf_cert = issue_cert(cn: "leaf", issuer: ca_cert, issuer_key: ca_key)

    p12 = OpenSSL::PKCS12.create("pass", "myalias", @key, leaf_cert, [ca_cert])
    parsed = OpenSSL::PKCS12.new(p12.to_der, "pass")
    assert_equal leaf_cert.subject.to_s, parsed.certificate.subject.to_s
    assert_equal 1, parsed.ca_certs.size
    assert_equal ca_cert.subject.to_s, parsed.ca_certs.first.subject.to_s
  end

  private

  def issue_cert(cn: "test", key: nil, issuer: nil, issuer_key: nil)
    key ||= @key
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse("/CN=#{cn}")
    cert.issuer = issuer ? issuer.subject : cert.subject
    cert.not_before = Time.now
    cert.not_after = Time.now + 3600
    cert.public_key = key.public_key
    cert.sign(issuer_key || key, OpenSSL::Digest::SHA256.new)
    cert
  end

end
