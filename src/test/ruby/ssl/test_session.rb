# coding: US-ASCII

require File.expand_path('test_helper', File.dirname(__FILE__))

class TestSSLSession < TestCase
  include SSLTestHelper

  def test_session
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |_server, port|
      sock = TCPSocket.new('127.0.0.1', port)
      ctx = OpenSSL::SSL::SSLContext.new('TLSv1_2')
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.sync_close = true
      ssl.connect

      assert ssl.session.is_a?(OpenSSL::SSL::Session)
      assert ssl.session.equal? session = ssl.session

      assert session.id.is_a?(String)
      assert_equal 32, session.id.length
      assert session.time.is_a?(Time)

      assert session.timeout >= 0

      session.timeout = 5
      assert_equal 5, session.timeout

      assert session == OpenSSL::SSL::Session.new(ssl)

      ssl.close
    end
  end

  def test_alpn_protocol_selection_ary
    advertised = ['h2', 'http/1.1']
    ctx_proc = proc do |ctx|
      ctx.alpn_select_cb = lambda { |protocols|
        assert_equal Array, protocols.class
        assert_equal advertised, protocols
        protocols.first
      }
    end
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, ctx_proc: ctx_proc) do |_server, port|
      sock = TCPSocket.new('127.0.0.1', port)
      ctx = OpenSSL::SSL::SSLContext.new('TLSv1_2')
      ctx.alpn_protocols = advertised
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.sync_close = true
      ssl.connect
      assert_equal('h2', ssl.alpn_protocol)
      ssl.puts 'abc'
      assert_equal "abc\n", ssl.gets
    end
  end

  def test_session_reuse
    ctx_proc = proc { |ctx|
      ctx.options &= ~OpenSSL::SSL::OP_NO_TICKET
    }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, ctx_proc: ctx_proc) do |_server, port|
      # first connection: establish session
      sock = TCPSocket.new('127.0.0.1', port)
      ctx = OpenSSL::SSL::SSLContext.new('TLSv1_2')
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.sync_close = true
      ssl.connect
      ssl.puts 'ping'
      assert_equal "ping\n", ssl.gets
      sess1 = ssl.session
      assert_instance_of OpenSSL::SSL::Session, sess1
      ssl.close

      # second connection: resume with captured session
      sock2 = TCPSocket.new('127.0.0.1', port)
      ctx2 = OpenSSL::SSL::SSLContext.new('TLSv1_2')
      ssl2 = OpenSSL::SSL::SSLSocket.new(sock2, ctx2)
      ssl2.sync_close = true
      ssl2.session = sess1
      ssl2.connect
      ssl2.puts 'pong'
      assert_equal "pong\n", ssl2.gets

      assert_equal sess1.id, ssl2.session.id, 'session id should match after resumption'
      assert ssl2.session_reused?, 'session_reused? should be truthy for resumed session'
      ssl2.close

      # third connection without session set: should NOT reuse
      sock3 = TCPSocket.new('127.0.0.1', port)
      ctx3 = OpenSSL::SSL::SSLContext.new('TLSv1_2')
      ssl3 = OpenSSL::SSL::SSLSocket.new(sock3, ctx3)
      ssl3.sync_close = true
      ssl3.connect
      ssl3.puts 'fresh'
      assert_equal "fresh\n", ssl3.gets
      # new connection without session= gets a different session
      refute_equal sess1.id, ssl3.session.id, 'fresh connection should get new session'
      ssl3.close
    end
  end

  def test_exposes_session_error
    OpenSSL::SSL::Session::SessionError
  end
end
