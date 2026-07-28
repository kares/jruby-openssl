# coding: US-ASCII
require File.expand_path('../test/test_helper', File.dirname(__FILE__))

require 'json'
require 'uri'
require 'net/https'

class IntegrationSSLTest < TestCase

  def test_connect_net_http_base
    uri = URI.parse('https://rubygems.org')
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    res = http.get('/')
    assert_equal Net::HTTPOK, res.class
  end

  # www.howsmyssl.com/a/check reports back what was actually negotiated, so the requested
  # ssl_version can be asserted instead of only checking that the server answered
  def test_connect_net_http_tls12
    uri = URI.parse('https://www.howsmyssl.com/a/check')
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.ssl_version = :TLSv1_2
    res = http.get(uri.path, 'Content-Type' => 'application/json')
    assert_equal Net::HTTPOK, res.class

    info = JSON.parse(res.body)
    assert_equal 'TLS 1.2', info['tls_version'],
                 "expected the negotiated version to match ssl_version (got #{info['tls_version']})"
  end

  def test_connect_net_http_tls13
    uri = URI.parse('https://check-tls.akamai.io/v1/tlsinfo.json')
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.ssl_version = :TLSv1_3
    res = http.get(uri.path, 'Accept' => 'application/json', 'User-Agent' => '')
    assert_equal '200', res.code

    info = JSON.parse(res.body)
    assert_equal 'tls1.3', info['tls_version'],
                 "expected the negotiated version to match ssl_version (got #{info['tls_version']})"
    # SNI has to reach the server for it to serve (and report) the right vhost
    assert_equal 'present', info['tls_sni_status']
    assert_equal uri.host, info['tls_sni_value']
  end

  def test_connect_net_http_other
    uri = URI.parse('https://s3.fr-par.scw.cloud')
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    res = http.get('/')
    assert_equal Net::HTTPOK, res.class
  end

  def test_faraday_get; require 'faraday'
    res = Faraday.get('https://httpbingo.org/ip')
    assert_equal 200, res.status
  end

  def test_connect_ssl_minmax_version; require 'socket'
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.min_version = OpenSSL::SSL::TLS1_1_VERSION
    ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION
    client = TCPSocket.new('google.co.uk', 443)
    ssl = OpenSSL::SSL::SSLSocket.new(client, ctx)
    ssl.sync_close = true
    ssl.connect
    begin
      assert_equal 'TLSv1.2', ssl.ssl_version
    ensure
      ssl.sysclose
    end
  end

  # Manticore is a pure Java client (Apache HttpClient 4.x) and does NOT use OpenSSL
  def test_java_baseline_tls13_without_jruby_openssl; require 'manticore'
    url = 'https://check-tls.akamai.io/v1/tlsinfo.json'
    client = Manticore::Client.new(ssl: { verify: :strict, protocols: ['TLSv1.3'] })
    response = client.get(url, headers: {}).call
    assert response.code < 400

    assert_equal 'tls1.3', JSON.parse(response.body)['tls_version']
    # NOTE: ['TLSv1.3'] fails on older Java 8/11 versions, despite supporting
    #   - TLS_AES_128_GCM_SHA256
    #   - TLS_AES_256_GCM_SHA384
  end if defined? JRUBY_VERSION

end
