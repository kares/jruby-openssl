/*
 * The MIT License
 *
 * Copyright 2014 Karol Bucek.
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

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.net.ssl.SSLContext;

import org.jruby.util.SafePropertyAccessor;

import static org.jruby.ext.openssl.OpenSSL.debug;
import static org.jruby.ext.openssl.OpenSSL.debugStackTrace;

/**
 * Java Security (and JCE) helpers.
 *
 * @author kares
 */
public abstract class SecurityHelper {

    static final String BC_PROVIDER_CLASS = "org.bouncycastle.jce.provider.BouncyCastleProvider";
    static final String BC_PROVIDER_NAME = "BC";
    static final String BC_FIPS_PROVIDER_CLASS = "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider";
    static final String BC_FIPS_PROVIDER_NAME = "BCFIPS";

    static volatile boolean initSecurityProvider = true;
    static volatile Provider securityProvider; // 'BC' (or 'BCFIPS') provider
    static volatile Boolean registerProvider;

    static final String BC_JSSE_PROVIDER_CLASS = "org.bouncycastle.jsse.provider.BouncyCastleJsseProvider";
    static volatile boolean initJsseProvider = true;
    static volatile Provider jsseProvider;

    /**
     * @implNote needs to be lazy; happen after {@link #setFipsMode(boolean)}
     * @return BC security provider
     */
    public static Provider getSecurityProvider() {
        Provider provider = securityProvider;
        if (provider == null && initSecurityProvider) {
            provider = initSecurityProvider();
            if (provider != null) doRegisterProvider(provider);
        }
        return provider;
    }

    private static synchronized Provider initSecurityProvider() {
        Provider provider = securityProvider;
        if (provider == null && initSecurityProvider) {
            final String providerName = isFipsMode() ? BC_FIPS_PROVIDER_NAME : BC_PROVIDER_NAME;
            // reuse when provider already registered (e.g. via java.security configuration)
            provider = Security.getProvider(providerName);
            if (provider != null) {
                debug("[JOpenSSL] reusing registered (security) provider: " + providerName);
                setSecurityProvider(provider, false);
            } else {
                final String className = isFipsMode() ? BC_FIPS_PROVIDER_CLASS : BC_PROVIDER_CLASS;
                provider = setBouncyCastleProvider(className);
            }
            initSecurityProvider = false;
        }
        return provider;
    }

    public static synchronized void setSecurityProvider(final Provider provider) {
        setSecurityProvider(provider, true);
    }

    private static synchronized void setSecurityProvider(final Provider provider, final boolean log) {
        if (provider != null && log) debug("[JOpenSSL] using (security) provider: " + provider);
        securityProvider = provider;
    }

    static Provider setBouncyCastleProvider(final String className) {
        Provider provider = newBouncyCastleProvider(className);
        setSecurityProvider(provider);
        return provider;
    }

    /**
     * @return BCJSSE (SSL SPI) provider
     */
    static Provider getJsseProvider() {
        Provider provider = jsseProvider;
        if (provider == null && initJsseProvider) provider = initJsseProvider(sslProviderName);
        return provider;
    }

    private static synchronized Provider initJsseProvider(final String name) {
        Provider provider = jsseProvider;
        if (provider == null && initJsseProvider) {
            if (name != null) {
                provider = Security.getProvider(name);
                if (provider != null) {
                    debug("[JOpenSSL] reusing registered ssl provider: " + name);
                }
            }
            if (provider == null && "BCJSSE".equals(name)) {
                provider = newBouncyCastleJsseProvider();
            } else if (provider == null && name != null) {
                debug("[JOpenSSL] unknown ssl provider name: " + name);
            }
            jsseProvider = provider; // even if null - we can operate without jsse provider
            initJsseProvider = false;
        }
        return provider;
    }

    private static Provider newBouncyCastleJsseProvider() {
        try {
            final Class<? extends Provider> providerClass =
                    (Class<? extends Provider>) Class.forName(BC_JSSE_PROVIDER_CLASS);
            final Provider cryptoProvider = getSecurityProvider();
            // default JDK providers lack algorithms BCJSSE's TLS 1.3 needs (e.g. X25519)
            if (cryptoProvider != null) {
                if (isFipsMode()) { // fipsMode: true so BCJSSE operates with FIPS constraints
                    return providerClass.getConstructor(boolean.class, Provider.class)
                            .newInstance(true, cryptoProvider);
                }
                return providerClass.getConstructor(Provider.class).newInstance(cryptoProvider);
            } else {
                debug("[JOpenSSL] instantiating ssl provider without BC crypto provider " +
                        "(features such as TLS key_share extension will be limited)");
                return providerClass.newInstance();
            }
        } catch (ReflectiveOperationException ex) {
            debug("[JOpenSSL] WARN: can not instantiate JSSE provider (" + BC_JSSE_PROVIDER_CLASS + ")", ex);
        }
        return null;
    }

    private static Provider newBouncyCastleProvider(final String klass) {
        try {
            return (Provider) Class.forName(klass).newInstance();
        } catch (ReflectiveOperationException ex) {
            debug("[JOpenSSL] WARN: can not instantiate provider (" + klass  + ")", ex);
        }
        return null;
    }

    private static final AtomicInteger FIPS_MODE = new AtomicInteger();
    private static final int FIPS_MODE_TRUE = 1;
    private static final int FIPS_MODE_FALSE = -1;

    public static boolean isFipsMode() {
        assert FIPS_MODE.get() != 0;
        return FIPS_MODE.get() == FIPS_MODE_TRUE;
    }

    static void setFipsMode(final boolean fipsMode) {
        final int fipsModeValue = fipsMode ? FIPS_MODE_TRUE : FIPS_MODE_FALSE;
        if (FIPS_MODE.get() == 0) FIPS_MODE.set(fipsModeValue);
        if (FIPS_MODE.get() != fipsModeValue) {
            throw new SecurityException("[JOpenSSL] unexpected FIPS mode adjustment (" + fipsMode + ")");
        }
    }

    /**
     * @implNote execute {@link #setFipsMode(boolean)} BEFORE
     */
    static void checkAndRegisterProviderOnce() {
        if (securityProvider != null) return;

        final String register = SafePropertyAccessor.getProperty("jruby.openssl.provider.register");
        setRegisterProvider(register == null ? isFipsMode() : Boolean.parseBoolean(register));
    }

    static synchronized void setRegisterProvider(final boolean register) {
        registerProvider = Boolean.valueOf(register);
        Provider provider = securityProvider;
        if (provider != null) doRegisterProvider(provider);
    }

    static boolean isProviderAvailable(final String name) {
        return Security.getProvider(name) != null;
    }

    static boolean isProviderRegistered() {
        if (securityProvider == null) return false;
        return isProviderAvailable(securityProvider.getName());
    }

    private static void doRegisterProvider(final Provider securityProvider) {
        if (registerProvider != null) {
            synchronized(SecurityHelper.class) {
                final Boolean register = registerProvider;
                if (register != null && register.booleanValue()) {
                    if (securityProvider != null) {
                        Security.addProvider(securityProvider);
                        registerProvider = null;
                    }
                }
            }
        }
    }

    public static CertificateFactory getCertificateFactory(final String type)
        throws CertificateException {
        try {
            final Provider provider = getSecurityProvider();
            if ( provider != null ) return getCertificateFactory(type, provider);
        }
        catch (CertificateException e) { debugStackTrace(e); }
        return CertificateFactory.getInstance(type);
    }

    static CertificateFactory getCertificateFactory(final String type, final Provider provider)
        throws CertificateException {
        return CertificateFactory.getInstance(type, provider);
    }

    public static KeyFactory getKeyFactory(final String algorithm) throws NoSuchAlgorithmException {
        try {
            final Provider provider = getSecurityProvider();
            if (provider != null) return getKeyFactory(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) { debug("getKeyFactory", e); }
        return KeyFactory.getInstance(algorithm);
    }

    static KeyFactory getKeyFactory(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return KeyFactory.getInstance(algorithm, provider);
    }

    public static KeyPairGenerator getKeyPairGenerator(final String algorithm)
        throws NoSuchAlgorithmException {
        try {
            final Provider provider = getSecurityProvider();
            if (provider != null) return getKeyPairGenerator(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) { debug("getKeyPairGenerator", e); }
        return KeyPairGenerator.getInstance(algorithm);
    }

    static KeyPairGenerator getKeyPairGenerator(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return KeyPairGenerator.getInstance(algorithm, provider);
    }

    public static KeyStore getKeyStore(final String type) throws KeyStoreException {
        try {
            final Provider provider = getSecurityProvider();
            if (provider != null) return getKeyStore(type, provider);
        }
        catch (KeyStoreException e) { debug("getKeyStore", e); }
        return KeyStore.getInstance(type);
    }

    static KeyStore getKeyStore(final String type, final Provider provider) throws KeyStoreException {
        return KeyStore.getInstance(type, provider);
    }

    public static MessageDigest getMessageDigest(final String algorithm) throws NoSuchAlgorithmException {
        try {
            return MessageDigest.getInstance(algorithm);
        }
        catch (NoSuchAlgorithmException e) {
            // try reflective logic
            final Provider provider = getSecurityProvider();
            if (provider != null) {
                debug("getMessageDigest", e);
                return getMessageDigest(algorithm, provider);
            }

            throw e; // give up
        }
    }

    static MessageDigest getMessageDigest(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(algorithm, provider);
    }

    public static SecureRandom getSecureRandom() {
        try {
            final Provider provider = getSecurityProvider();
            if (provider != null) {
                final String algorithm = getSecureRandomAlgorithm(provider);
                if (algorithm != null) return getSecureRandom(algorithm, provider);
            }
        }
        catch (NoSuchAlgorithmException e) { debug("getSecureRandom", e); }
        return new SecureRandom();
    }

    private static SecureRandom getSecureRandom(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return SecureRandom.getInstance(algorithm, provider);
    }

    private static String getSecureRandomAlgorithm(final Provider provider) {
        for (Provider.Service service : provider.getServices()) {
            if ("SecureRandom".equals(service.getType())) return service.getAlgorithm();
        }
        return null;
    }

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static Cipher getCipher(final String transformation)
        throws NoSuchAlgorithmException, NoSuchPaddingException {
        try {
            final Provider provider = getSecurityProvider();
            if (provider != null) return getCipher(transformation, provider);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException e) { debug("getCipher", e); }
        return Cipher.getInstance(transformation);
    }

    static Cipher getCipher(final String transformation, final Provider provider)
        throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance(transformation, provider);
    }

    public static Signature getSignature(final String algorithm) throws NoSuchAlgorithmException {
        try {
            final Provider provider = getSecurityProvider();
            if (provider != null) return getSignature(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) { debug("getSignature", e); }
        return Signature.getInstance(algorithm);
    }

    static Signature getSignature(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return Signature.getInstance(algorithm, provider);
    }

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static Mac getMac(final String algorithm) throws NoSuchAlgorithmException {
        Mac mac = null;
        final Provider provider = getSecurityProvider();
        if (provider != null) {
            mac = getMac(algorithm, provider, true);
        }
        if (mac == null) mac = Mac.getInstance(algorithm);
        return mac;
    }

    static Mac getMac(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return getMac(algorithm, provider, false);
    }

    private static Mac getMac(final String algorithm, final Provider provider, boolean silent)
        throws NoSuchAlgorithmException {
        try {
            return Mac.getInstance(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) {
            if ( silent ) return null;
            throw e;
        }
    }

    public static KeyGenerator getKeyGenerator(final String algorithm) throws NoSuchAlgorithmException {
        try {
            final Provider provider = getSecurityProvider();
            if (provider != null) return getKeyGenerator(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) { debug("getKeyGenerator", e); }
        catch (SecurityException e) { debugStackTrace(e); }
        return KeyGenerator.getInstance(algorithm);
    }

    static KeyGenerator getKeyGenerator(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return KeyGenerator.getInstance(algorithm, provider);
    }

    public static KeyAgreement getKeyAgreement(final String algorithm) throws NoSuchAlgorithmException {
        try {
            final Provider provider = getSecurityProvider();
            if (provider != null) return getKeyAgreement(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) { debug("getKeyAgreement", e); }
        catch (SecurityException e) { debugStackTrace(e); }
        return KeyAgreement.getInstance(algorithm);
    }

    static KeyAgreement getKeyAgreement(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return KeyAgreement.getInstance(algorithm, provider);
    }

    public static SecretKeyFactory getSecretKeyFactory(final String algorithm) throws NoSuchAlgorithmException {
        try {
            final Provider provider = getSecurityProvider();
            if (provider != null) return getSecretKeyFactory(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) { debug("getSecretKeyFactory", e); }
        catch (SecurityException e) { debugStackTrace(e); }
        return SecretKeyFactory.getInstance(algorithm);
    }

    static SecretKeyFactory getSecretKeyFactory(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return SecretKeyFactory.getInstance(algorithm, provider);
    }

    private static final String sslProviderName;
    static {
        String sslProvider = SafePropertyAccessor.getProperty("jruby.openssl.provider.ssl", "BCJSSE");
        switch (sslProvider.trim()) {
            case "BC": case "bc": case "bcjsse": case "BCJSSE": case "true":
                sslProvider = "BCJSSE";
                break;
            case "": case "false":
                sslProvider = null; // usually SunJSSE (default) on OpenJDK
                break;
        }
        sslProviderName = sslProvider;
    }

    public static SSLContext getSSLContext(final String protocol) throws NoSuchAlgorithmException {
        try {
            if (sslProviderName == "BCJSSE" && !"SSL".equals(protocol)) { // only TLS supported in BCJSSE
                final Provider provider = getJsseProvider();
                if (provider != null) return getSSLContext(protocol, provider);
            }
        }
        catch (NoSuchAlgorithmException e) { debug("getSSLContext", e); }
        return SSLContext.getInstance(protocol); // built-in (SunJSSE) provider
    }

    private static SSLContext getSSLContext(final String protocol, final Provider provider)
        throws NoSuchAlgorithmException {
        return SSLContext.getInstance(protocol, provider);
    }

    public static boolean verify(final X509CRL crl, final PublicKey publicKey)
        throws NoSuchAlgorithmException, CRLException, InvalidKeyException, SignatureException {
        return verify(crl, publicKey, false);
    }

    static boolean verify(final X509CRL crl, final PublicKey publicKey, final boolean silent)
        throws NoSuchAlgorithmException, CRLException, InvalidKeyException, SignatureException {
        try {
            final Provider provider = securityProvider;
            if (provider != null) {
                crl.verify(publicKey, provider);
            }
            else {
                crl.verify(publicKey);
            }
            return true;
        }
        catch (SignatureException e) {
            if (silent) return false;
            throw e;
        }
        catch (NoSuchProviderException e) {
            if (silent) return false;
            throw new SignatureException(e);
        }
    }
}
