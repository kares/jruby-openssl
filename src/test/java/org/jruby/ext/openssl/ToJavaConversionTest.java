package org.jruby.ext.openssl;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.Mac;
import javax.security.auth.x500.X500Principal;

import org.jruby.ext.openssl.x509store.X509AuxCertificate;
import org.jruby.runtime.builtin.IRubyObject;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * to_java conversions of Ruby OpenSSL objects wrapping Java objects
 */
public class ToJavaConversionTest extends OpenSSLHelper {

    @BeforeEach
    public void setUp() throws Exception {
        setUpRuntime();
        // shared RSA key + self-signed cert for the cert/name/crl cases
        runtime.evalScriptlet(
            "$key = OpenSSL::PKey::RSA.new(2048)\n" +
            "$cert = OpenSSL::X509::Certificate.new\n" +
            "$cert.version = 2; $cert.serial = 1\n" +
            "$cert.subject = $cert.issuer = OpenSSL::X509::Name.parse('/DC=org/CN=ToJava Test')\n" +
            "$cert.public_key = $key.public_key\n" +
            "$cert.not_before = Time.now - 3600; $cert.not_after = Time.now + 3600\n" +
            "$cert.sign($key, OpenSSL::Digest::SHA256.new)\n");
    }

    @AfterEach
    public void tearDown() {
        tearDownRuntime();
    }

    private IRubyObject eval(final String script) {
        return runtime.evalScriptlet(script);
    }

    @Test
    public void bnToJava() {
        IRubyObject bn = eval("OpenSSL::BN.new('4242')");
        assertEquals(BigInteger.valueOf(4242), bn.toJava(BigInteger.class));
        assertEquals(BigInteger.valueOf(4242), bn.toJava(Object.class));
        assertEquals(Long.valueOf(4242), bn.toJava(Long.class));
        assertEquals(Integer.valueOf(4242), bn.toJava(Integer.class));
    }

    @Test
    public void pKeyToJava() {
        IRubyObject key = eval("$key");
        assertNotNull(key.toJava(PublicKey.class));
        assertTrue(key.toJava(PublicKey.class) instanceof RSAPublicKey);
        assertTrue(key.toJava(RSAPublicKey.class) instanceof RSAPublicKey);
        assertTrue(key.toJava(PrivateKey.class) instanceof RSAPrivateKey);
        assertTrue(key.toJava(RSAPrivateKey.class) instanceof RSAPrivateKey);
        assertTrue(key.toJava(Key.class) instanceof PublicKey); // default: public
    }

    @Test
    public void pKeyToKeyPair() {
        KeyPair pair = (KeyPair) eval("$key").toJava(KeyPair.class);
        assertTrue(pair.getPublic() instanceof RSAPublicKey);
        assertTrue(pair.getPrivate() instanceof RSAPrivateKey);

        // public-only key: KeyPair must not be constructible
        try {
            eval("$key.public_key").toJava(KeyPair.class);
            fail("expected conversion of public-only key to KeyPair to raise");
        } catch (org.jruby.exceptions.RaiseException e) {
            assertTrue(e.getMessage().contains("private key not available"), e.getMessage());
        }
    }

    @Test
    public void certToJava() {
        IRubyObject cert = eval("$cert");
        assertTrue(cert.toJava(X509Certificate.class) instanceof X509Certificate);
        assertTrue(cert.toJava(Certificate.class) instanceof X509Certificate);
        assertTrue(cert.toJava(Object.class) instanceof X509Certificate);
        // regression: X509AuxCertificate is a subclass - used to fall through to a TypeError
        assertTrue(cert.toJava(X509AuxCertificate.class) instanceof X509AuxCertificate);
    }

    @Test
    public void crlToJava() {
        IRubyObject crl = eval(
            "crl = OpenSSL::X509::CRL.new\n" +
            "crl.issuer = $cert.subject; crl.version = 1\n" +
            "crl.last_update = Time.now; crl.next_update = Time.now + 3600\n" +
            "crl.sign($key, OpenSSL::Digest::SHA256.new)\n" +
            "crl");
        assertTrue(crl.toJava(java.security.cert.X509CRL.class) instanceof java.security.cert.X509CRL);
        assertTrue(crl.toJava(java.security.cert.CRL.class) instanceof java.security.cert.X509CRL);
    }

    @Test
    public void nameToX500Principal() {
        IRubyObject name = eval("$cert.subject");
        X500Principal principal = (X500Principal) name.toJava(X500Principal.class);
        assertEquals(new X500Principal("CN=ToJava Test,DC=org"), principal);
        assertTrue(name.toJava(Principal.class) instanceof X500Principal);
        // to_java() (Object target) keeps returning the Ruby object
        assertSame(name, name.toJava(Object.class));
    }

    @Test
    public void digestToMessageDigest() throws Exception {
        IRubyObject digest = eval("d = OpenSSL::Digest::SHA256.new; d << 'to-java'; d");
        MessageDigest md = (MessageDigest) digest.toJava(MessageDigest.class);
        assertEquals("SHA-256", md.getAlgorithm());
        // live impl: completing it must match Ruby's result for the same data
        byte[] javaResult = md.digest();
        byte[] expected = MessageDigest.getInstance("SHA-256").digest("to-java".getBytes());
        assertArrayEquals(expected, javaResult);
        assertSame(digest, digest.toJava(Object.class));
    }

    @Test
    public void hmacToMac() {
        // key >= 112 bits - BC-FIPS approved-only rejects shorter HMAC keys
        IRubyObject hmac = eval("OpenSSL::HMAC.new('secret-key-32-bytes-in-length!!!', OpenSSL::Digest::SHA256.new)");
        Mac mac = (Mac) hmac.toJava(Mac.class);
        assertTrue(mac.getAlgorithm().toUpperCase().contains("SHA256"), mac.getAlgorithm());
        assertSame(hmac, hmac.toJava(Object.class));
    }

}
