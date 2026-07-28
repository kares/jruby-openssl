# coding: US-ASCII
require File.expand_path('../test/test_helper', File.dirname(__FILE__))

# Uses trocla (a real-world consumer) to generate a CA hierarchy and then verify
# it back - exercising cert generation, extensions and X509::Store verification
class IntegrationTroclaTest < TestCase

  def setup; require 'trocla'
    ca_str = trocla.password('my_shiny_selfsigned_ca', 'x509', ca_options)
    @ca = OpenSSL::X509::Certificate.new(ca_str)
  end

  def test_supports_simple_name_constraints_for_CAs
    ca2_str = trocla.password('mycert_with_nc', 'x509', cert_options.merge({
                                                                              'name_constraints' => ['example.com','bla.example.net'],
                                                                              'become_ca' => true,
                                                                          }))
    ca2 = OpenSSL::X509::Certificate.new(ca2_str)
    assert_equal ca2.issuer.to_s, @ca.subject.to_s
    # trocla defaults to a year of validity (the exact day depends on the local clock)
    assert_include 364..365, (Date.parse(ca2.not_after.localtime.to_s) - Date.today).to_i

    assert verify(@ca, ca2), @store.error_string

    assert_equal 'CA:TRUE', ca2.extensions.find { |e| e.oid == 'basicConstraints' }.value
    key_usage = ca2.extensions.find { |e| e.oid == 'keyUsage' }.value
    assert_match(/Certificate Sign/, key_usage)
    assert_match(/CRL Sign/, key_usage)

    name_constraints = ca2.extensions.find { |e| e.oid == 'nameConstraints' }
    assert name_constraints, 'nameConstraints extension missing'
    # NOTE: CRuby renders this as "Permitted:\n  DNS:example.com\n  DNS:bla.example.net" while
    # we still dump the raw ASN.1 - only assert on the content (see jruby/jruby#3502)
    assert_match(/example\.com/, name_constraints.value)
    assert_match(/bla\.example\.net/, name_constraints.value)
  end

  # the constraints are actually *enforced* when verifying certificates issued by that CA
  def test_enforces_name_constraints_when_verifying
    ca2 = OpenSSL::X509::Certificate.new(
        trocla.password('mycert_with_nc', 'x509', cert_options.merge({
                                                                         'name_constraints' => ['example.com','bla.example.net'],
                                                                         'become_ca' => true,
                                                                     })))

    valid_cert = OpenSSL::X509::Certificate.new(
        trocla.password('myvalidexamplecert', 'x509', {
            'subject' => '/C=ZZ/O=Trocla Inc./CN=foo.example.com/emailAddress=example@example.com',
            'ca' => 'mycert_with_nc'
        }))
    assert_equal ca2.subject.to_s, valid_cert.issuer.to_s
    assert verify([@ca, ca2], valid_cert), "permitted subtree must verify: #{@store.error_string}"

    # foo.example.net is outside the permitted subtrees
    false_cert = OpenSSL::X509::Certificate.new(
        trocla.password('myfalseexamplecert', 'x509', {
            'subject' => '/C=ZZ/O=Trocla Inc./CN=foo.example.net/emailAddress=example@example.com',
            'ca' => 'mycert_with_nc'
        }))
    assert_equal ca2.subject.to_s, false_cert.issuer.to_s
    assert_equal false, verify([@ca, ca2], false_cert), 'excluded name must not verify'
    assert_match(/subtree/i, @store.error_string)
  end

  define_method(:ca_options) do
    {
        'CN'        => 'This is my self-signed certificate which doubles as CA',
        'become_ca' => true,
    }
  end

  define_method(:cert_options) do
    {
        'ca'       => 'my_shiny_selfsigned_ca',
        'subject'  => '/C=ZZ/O=Trocla Inc./CN=test/emailAddress=example@example.com',
    }
  end

  protected

  def trocla
    @trocla ||= Trocla.new.tap do |trocla|
      default_config = trocla.send :default_config
      def trocla.default_config; @default_config end
      trocla.instance_variable_set :@default_config, default_config.merge({ 'store' => :memory })
    end
  end

  private

  def verify(ca, cert)
    @store = OpenSSL::X509::Store.new
    @store.purpose = OpenSSL::X509::PURPOSE_SSL_CLIENT
    Array(ca).each { |c| @store.add_cert(c) }
    @store.verify(cert)
  end

end
