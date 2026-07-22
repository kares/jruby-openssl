# coding: US-ASCII
#
# HTTPS round-trips adapted from ruby/net-http test/net/http/test_https.rb
# to exercise jruby-openssl client+server TLS in-repo (full suite: `rake net-http:test`)
#
require File.expand_path('../ssl/test_helper', File.dirname(__FILE__))

class TestHTTPS < TestCase

  include SSLTestHelper

  def self.startup; require 'net/https' end

  BODY = 'hello, https'.freeze

  def test_get
    https_server do |port, store|
      http = Net::HTTP.new('localhost', port)
      http.use_ssl = true
      http.cert_store = store
      http.request_get('/') do |res|
        assert_equal BODY, res.body
        assert_equal @svr_cert.to_der, http.peer_cert.to_der
      end
    end
  end

  def test_get_verify_none
    https_server do |port, _store|
      http = Net::HTTP.new('127.0.0.1', port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      http.request_get('/') { |res| assert_equal BODY, res.body }
    end
  end

  def test_verify_hostname_mismatch # connect IP != cert CN=localhost
    https_server do |port, store|
      http = Net::HTTP.new('127.0.0.1', port)
      http.use_ssl = true
      http.cert_store = store
      assert_raise(OpenSSL::SSL::SSLError) { http.start }
    end
  end

  def test_unknown_ca
    https_server do |port, _store|
      http = Net::HTTP.new('localhost', port)
      http.use_ssl = true
      http.cert_store = OpenSSL::X509::Store.new # empty -> unknown CA
      assert_raise(OpenSSL::SSL::SSLError) { http.start }
    end
  end

  private

  # minimal HTTPS server using SSLTestHelper's @svr_cert/@svr_key; yields (port, client_store)
  def https_server
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.cert = @svr_cert
    ctx.key  = @svr_key
    tcp = TCPServer.new('127.0.0.1', 0)
    ssl_server = OpenSSL::SSL::SSLServer.new(tcp, ctx)
    thread = Thread.new do
      loop do
        sock = ssl_server.accept rescue break
        begin
          sock.gets("\r\n\r\n")
          sock.write "HTTP/1.1 200 OK\r\nContent-Length: #{BODY.bytesize}\r\nConnection: close\r\n\r\n#{BODY}"
        rescue StandardError
        ensure
          sock.close rescue nil
        end
      end
    end
    store = OpenSSL::X509::Store.new
    store.add_cert(@ca_cert)
    yield tcp.addr[1], store
  ensure
    ssl_server.close rescue nil
    thread.kill rescue nil
  end

end
