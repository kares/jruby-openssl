# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))
require 'stringio'

class TestX509Context < TestCase
  def test_store_context_verify_failure_state
    _ca_cert, _intermediate_cert, ee_cert = issue_chain

    store = OpenSSL::X509::Store.new
    ctx = OpenSSL::X509::StoreContext.new(store, ee_cert)

    assert_nil ctx.current_cert
    assert_nil ctx.current_crl
    assert_equal false, ctx.verify
    assert_equal OpenSSL::X509::V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, ctx.error
    assert_match(/unable to get local issuer certificate/i, ctx.error_string)
    assert_equal 0, ctx.error_depth
    assert_equal [ee_cert], ctx.chain
    assert_equal ee_cert, ctx.current_cert
    assert_nil ctx.current_crl
  end

  def test_store_context_verify_with_untrusted_chain
    ca_cert, intermediate_cert, ee_cert = issue_chain

    store = OpenSSL::X509::Store.new
    store.add_cert(ca_cert)
    ctx = OpenSSL::X509::StoreContext.new(store, ee_cert, [intermediate_cert])

    assert_equal true, ctx.verify
    assert_equal OpenSSL::X509::V_OK, ctx.error
    assert_match(/ok/i, ctx.error_string)
    assert_equal [ee_cert, intermediate_cert, ca_cert], ctx.chain
  end

  def test_store_context_cleanup_is_deprecated_noop
    key = Fixtures.pkey('rsa-1.pem')
    cert = issue_cert(OpenSSL::X509::Name.parse_rfc2253('CN=Self Signed'), key, 1, [], nil, nil)
    store = OpenSSL::X509::Store.new
    ctx = OpenSSL::X509::StoreContext.new(store, cert, [])

    assert_equal false, ctx.verify
    assert_equal OpenSSL::X509::V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, ctx.error
    assert_match(/self.signed/i, ctx.error_string)
    assert_equal 0, ctx.error_depth

    stderr = capture_stderr { assert_nil ctx.cleanup }
    assert_match(/cleanup.*deprecated/, stderr)

    assert_equal OpenSSL::X509::V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, ctx.error
    assert_match(/self.signed/i, ctx.error_string)
    assert_equal 0, ctx.error_depth
  end

  def test_store_context_dup_clone_not_allowed
    store = OpenSSL::X509::Store.new
    ctx = OpenSSL::X509::StoreContext.new(store)

    assert_raise(NoMethodError) { ctx.dup }
    assert_raise(NoMethodError) { ctx.clone }
  end

  private

  def issue_chain
    ca_exts = [
      ['basicConstraints', 'CA:TRUE', true],
      ['keyUsage', 'cRLSign,keyCertSign', true],
    ]
    ca_name = OpenSSL::X509::Name.parse_rfc2253('CN=Root CA')
    ca_key = Fixtures.pkey('rsa-1.pem')
    ca_cert = issue_cert(ca_name, ca_key, 1, ca_exts, nil, nil)

    intermediate_name = OpenSSL::X509::Name.parse_rfc2253('CN=Intermediate CA')
    intermediate_key = Fixtures.pkey('rsa-2.pem')
    intermediate_cert = issue_cert(intermediate_name, intermediate_key, 2, ca_exts, ca_cert, ca_key)

    ee_exts = [
      ['keyUsage', 'keyEncipherment,digitalSignature', true],
    ]
    ee_name = OpenSSL::X509::Name.parse_rfc2253('CN=EE 1')
    ee_key = Fixtures.pkey('rsa2048')
    ee_cert = issue_cert(ee_name, ee_key, 10, ee_exts, intermediate_cert, intermediate_key)

    [ca_cert, intermediate_cert, ee_cert]
  end

  def capture_stderr
    stderr = StringIO.new
    old_stderr = $stderr
    $stderr = stderr
    yield
    stderr.string
  ensure
    $stderr = old_stderr
  end
end
