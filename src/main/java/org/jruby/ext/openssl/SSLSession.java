/*
 * The MIT License
 *
 * Copyright 2015 Karol Bucek.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jruby.ext.openssl;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import javax.net.ssl.SSLSessionContext;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.RubyTime;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.openssl.log.Logger;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;

import static org.jruby.ext.openssl.SSL._SSL;
import static org.jruby.ext.openssl.util.RubySupport.newString;

/**
 * OpenSSL::SSL::Session
 *
 * @author kares
 */
public class SSLSession extends RubyObject {

    private static final Logger LOG = Logger.getLogger(SSLSession.class);

    // 24h default in BCJSSE as well as SunJSSE (default in OpenSSL is 300)
    static final int DEFAULT_SESSION_TIMEOUT = 86400;

    private static final String PEM_BEGIN = "-----BEGIN SSL SESSION PARAMETERS-----";
    private static final String PEM_END = "-----END SSL SESSION PARAMETERS-----";

    static void createSession(final Ruby runtime, final RubyModule SSL, final RubyClass OpenSSLError) { // OpenSSL::SSL
        RubyClass Session = SSL.defineClassUnder("Session", runtime.getObject(), (r, klass) -> new SSLSession(r, klass));
        // OpenSSL::SSL::Session::SessionError
        Session.defineClassUnder("SessionError", OpenSSLError, OpenSSLError.getAllocator());
        Session.defineAnnotatedMethods(SSLSession.class);
    }

    private javax.net.ssl.SSLSession sslSession;

    SSLSession(Ruby runtime, RubyClass metaClass) {
        super(runtime, metaClass);
    }

    SSLSession(Ruby runtime) {
        this(runtime, (RubyClass) _SSL(runtime).getConstantAt("Session"));
    }

    SSLSession(Ruby runtime, javax.net.ssl.SSLSession session) {
        this(runtime);
        this.sslSession = session;
    }

    @JRubyMethod(name = "initialize", visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject arg) {
        if (arg instanceof SSLSocket) {
            return initializeImpl((SSLSocket) arg);
        }
        throw context.runtime.newNotImplementedError("OpenSSL::SSL::Session#initialize with non-SSL socket");
    }

    @JRubyMethod(name = "initialize_copy", visibility = Visibility.PRIVATE)
    public IRubyObject initialize_copy(final ThreadContext context, final IRubyObject other) {
        if (!(other instanceof SSLSession)) {
            throw context.runtime.newTypeError(other, getMetaClass());
        }
        final SSLSession that = (SSLSession) other;
        this.sslSession = that.sslSession;
        return this;
    }

    SSLSession initializeImpl(final SSLSocket socket) {
        sslSession = socket.sslSession();
        return this;
    }

    final javax.net.ssl.SSLSession sslSession() {
        return sslSession;
    }

    @JRubyMethod(name = "==")
    public IRubyObject op_eqq(final ThreadContext context, final IRubyObject other) {
        return context.runtime.newBoolean( equals(other) );
    }

    @Override
    public boolean equals(final Object other) {
        if (other instanceof SSLSession) {
            final SSLSession that = (SSLSession) other;
            final String thisProtocol = this.getProtocol();
            final String thatProtocol = that.getProtocol();
            if (thisProtocol == null || thatProtocol == null) return false;
            return thisProtocol.equals(thatProtocol) && Arrays.equals(getIdBytes(), that.getIdBytes());
        }
        return false;
    }

    @Override
    public final int hashCode() {
        int hash = Arrays.hashCode(getIdBytes());
        final String proto = getProtocol();
        hash = 31 * hash + (proto == null ? 0 : proto.hashCode());
        return hash;
    }

    @Override
    public RubyFixnum hash() {
        return getRuntime().newFixnum(hashCode());
    }

    @JRubyMethod(name = "id")
    public RubyString id(final ThreadContext context) {
        return newString(context.runtime, getIdBytes());
    }

    @JRubyMethod(name = "id=")
    public IRubyObject set_id(final ThreadContext context, IRubyObject id) {
        LOG.debug(context.runtime, "id= is not supported");
        return context.nil;
    }

    @JRubyMethod(name = "time")
    public RubyTime time(final ThreadContext context) {
        final long time = sslSession().getCreationTime();
        return RubyTime.newTime(context.runtime, time);
    }

    @JRubyMethod(name = "time=")
    public IRubyObject set_time(final ThreadContext context, IRubyObject time) {
        LOG.debug(context.runtime, "time= is not supported");
        return context.nil;
    }

    @JRubyMethod(name = "timeout")
    public IRubyObject timeout(final ThreadContext context) {
        return context.runtime.newFixnum(getTimeout());
    }

    private int getTimeout() {
        final SSLSessionContext sessionContext = sslSession.getSessionContext();
        if (sessionContext == null) return DEFAULT_SESSION_TIMEOUT;
        return sessionContext.getSessionTimeout();
    }

    @JRubyMethod(name = "timeout=")
    public IRubyObject set_timeout(final ThreadContext context, IRubyObject timeout) {
        final SSLSessionContext sessionContext = sslSession().getSessionContext();
        if (sessionContext == null) return context.nil;

        try {
            sessionContext.setSessionTimeout(RubyNumeric.fix2int(timeout)); // in seconds as well
        } catch (IllegalArgumentException e) {
            throw context.runtime.newArgumentError(e.getMessage());
        }
        return timeout(context);
    }

    @JRubyMethod(name = "to_der")
    public RubyString to_der(final ThreadContext context) {
        try {
            return newString(context.runtime, buildDERSequence().getEncoded());
        } catch (IOException e) {
            throw context.runtime.newRuntimeError(e.getMessage());
        }
    }

    @JRubyMethod(name = "to_pem")
    public RubyString to_pem(final ThreadContext context) {
        final byte[] derBytes;
        try {
            derBytes = buildDERSequence().getEncoded();
        } catch (IOException e) {
            throw context.runtime.newRuntimeError(e.getMessage());
        }
        final String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(derBytes);
        return newString(context.runtime, PEM_BEGIN + "\n" + base64 + "\n" + PEM_END);
    }

    @JRubyMethod(name = "to_text")
    public RubyString to_text(final ThreadContext context) {
        final StringBuilder text = new StringBuilder(192);
        text.append("SSL-Session:\n");
        text.append("    Protocol  : ").append(getProtocol()).append('\n');
        text.append("    Session-ID: ").append(toHex(getIdBytes())).append('\n');
        text.append("    Time      : ").append(getTimeInSeconds()).append('\n');
        text.append("    Timeout   : ").append(getTimeout()).append(" (sec)\n");
        return newString(context.runtime, text);
    }

    @Override
    public <T> T toJava(final Class<T> target) {
        if (target.isAssignableFrom(getClass())) return (T) this;
        if (target.isInstance(sslSession) ) return (T) sslSession;
        return super.toJava(target);
    }

    private byte[] getIdBytes() {
        if (sslSession != null) return sslSession.getId();
        return new byte[0];
    }

    private String getProtocol() {
        if (sslSession != null) return sslSession.getProtocol();
        return null;
    }

    private long getTimeInSeconds() {
        return sslSession.getCreationTime() / 1000;
    }

    private DERSequence buildDERSequence() {
        final ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(1L));
        v.add(new ASN1Integer((long) versionFromProtocol(getProtocol())));
        v.add(new DEROctetString(new byte[] { 0x00, 0x00 }));
        v.add(new DEROctetString(getIdBytes()));
        v.add(new DEROctetString(new byte[0]));

        final long time = getTimeInSeconds();
        v.add(new DERTaggedObject(true, 1, new ASN1Integer(time)));
        v.add(new DERTaggedObject(true, 2, new ASN1Integer((long) getTimeout())));
        return new DERSequence(v);
    }

    private static int versionFromProtocol(final String protocol) {
        if ("SSLv3".equals(protocol)) return 0x0300;
        if ("TLSv1".equals(protocol)) return 0x0301;
        if ("TLSv1.1".equals(protocol)) return 0x0302;
        if ("TLSv1.3".equals(protocol)) return 0x0304;
        return 0x0303; // MRI assumes "TLSv1.2" default
    }

    private static StringBuilder toHex(final byte[] bytes) {
        final StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            final int v = b & 0xFF;
            if (v < 16) hex.append('0');
            hex.append(Integer.toHexString(v).toUpperCase());
        }
        return hex;
    }

}
