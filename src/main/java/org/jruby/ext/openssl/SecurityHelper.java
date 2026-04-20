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

    static final boolean FIPS_MODE = SafePropertyAccessor.getBoolean("jruby.openssl.provider.fips");

    private static final String BC_PROVIDER_CLASS = FIPS_MODE ?
        "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider" :
        "org.bouncycastle.jce.provider.BouncyCastleProvider";
    static boolean setBouncyCastleProvider = true; // (package access for tests)
    static volatile Provider securityProvider; // 'BC' provider (package access for tests)
    private static volatile Boolean registerProvider = null;

    private static String BCJSSE_PROVIDER_CLASS = "org.bouncycastle.jsse.provider.BouncyCastleJsseProvider";
    static boolean setJsseProvider = true;
    static volatile Provider jsseProvider;

    public static Provider getSecurityProvider() {
        Provider provider = securityProvider;
        if ( setBouncyCastleProvider && provider == null ) {
            synchronized(SecurityHelper.class) {
                provider = securityProvider;
                if ( setBouncyCastleProvider && provider == null ) {
                    provider = setBouncyCastleProvider();
                    setBouncyCastleProvider = false;
                }
            }
        }
        doRegisterProvider(provider);
        return provider;
    }

    public static boolean isFipsMode() {
        return FIPS_MODE;
    }

    private static Provider getJsseProvider(final String name) {
        Provider provider = jsseProvider;
        if ( setJsseProvider && provider == null ) {
            synchronized(SecurityHelper.class) {
                provider = jsseProvider;
                if ( setJsseProvider && provider == null ) {
                    try {
                        provider = Security.getProvider(name);
                    }
                    catch (Exception ex) {
                        debug("failed to get provider: " + name, ex);
                    }
                    if (provider == null && "BCJSSE".equals(name)) {
                        provider = newBouncyCastleProvider(BCJSSE_PROVIDER_CLASS);
                    }
                    jsseProvider = provider; setJsseProvider = false;
                }
            }
        }
        return provider;
    }


    public static synchronized void setSecurityProvider(final Provider provider) {
        if ( provider != null ) debug("using (security) provider: " + provider);
        securityProvider = provider;
    }

    static synchronized Provider setBouncyCastleProvider() {
        Provider provider = newBouncyCastleProvider(BC_PROVIDER_CLASS);
        setSecurityProvider(provider);
        return provider;
    }

    private static Provider newBouncyCastleProvider(final String klass) {
        try {
            return (Provider) Class.forName(klass).newInstance();
        }
        catch (Throwable ignored) {
            debug("can not instantiate bouncy-castle provider (" + klass  + ")", ignored);
        }
        return null;
    }

    public static synchronized void setRegisterProvider(final boolean register) {
        registerProvider = Boolean.valueOf(register);
        if ( register ) getSecurityProvider(); // so that securityProvider != null
        // getSecurityProvider does doRegisterProvider();
    }

    static boolean isProviderAvailable(final String name) {
        return Security.getProvider(name) != null;
    }

    public static boolean isProviderRegistered() {
        if ( securityProvider == null ) return false;
        return Security.getProvider(securityProvider.getName()) != null;
    }

    private static void doRegisterProvider(final Provider securityProvider) {
        if ( registerProvider != null ) {
            synchronized(SecurityHelper.class) {
                final Boolean register = registerProvider;
                if ( register != null && register.booleanValue() ) {
                    if ( securityProvider != null ) {
                        Security.addProvider(securityProvider);
                        registerProvider = null;
                    }
                }
            }
        }
    }

    /**
     * @note code calling this should not assume BC provider internals !
     */
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

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static KeyFactory getKeyFactory(final String algorithm)
        throws NoSuchAlgorithmException {
        try {
            final Provider provider = getSecurityProvider();
            if ( provider != null ) return getKeyFactory(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) { }
        return KeyFactory.getInstance(algorithm);
    }

    static KeyFactory getKeyFactory(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return KeyFactory.getInstance(algorithm, provider);
    }

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static KeyPairGenerator getKeyPairGenerator(final String algorithm)
        throws NoSuchAlgorithmException {
        try {
            final Provider provider = getSecurityProvider();
            if ( provider != null ) return getKeyPairGenerator(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) { }
        return KeyPairGenerator.getInstance(algorithm);
    }

    @SuppressWarnings("unchecked")
    static KeyPairGenerator getKeyPairGenerator(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return KeyPairGenerator.getInstance(algorithm, provider);
    }

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static KeyStore getKeyStore(final String type)
        throws KeyStoreException {
        try {
            final Provider provider = getSecurityProvider();
            if ( provider != null ) return getKeyStore(type, provider);
        }
        catch (KeyStoreException e) { }
        return KeyStore.getInstance(type);
    }

    static KeyStore getKeyStore(final String type, final Provider provider)
        throws KeyStoreException {
        return KeyStore.getInstance(type, provider);
    }

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static MessageDigest getMessageDigest(final String algorithm) throws NoSuchAlgorithmException {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException nsae) {
            // try reflective logic
            final Provider provider = getSecurityProvider();
            if ( provider != null ) return getMessageDigest(algorithm, provider);

            throw nsae; // give up
        }
    }

    @SuppressWarnings("unchecked")
    static MessageDigest getMessageDigest(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(algorithm, provider);
    }

    public static SecureRandom getSecureRandom() {
        try {
            final Provider provider = getSecurityProvider();
            if ( provider != null ) {
                final String algorithm = getSecureRandomAlgorithm(provider);
                if ( algorithm != null ) {
                    return getSecureRandom(algorithm, provider);
                }
            }
        }
        catch (NoSuchAlgorithmException e) { }
        return new SecureRandom();
    }

    private static SecureRandom getSecureRandom(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return SecureRandom.getInstance(algorithm, provider);
    }

    // NOTE: none (at least for BC 1.47)
    private static String getSecureRandomAlgorithm(final Provider provider) {
        for ( Provider.Service service : provider.getServices() ) {
            if ( "SecureRandom".equals( service.getType() ) ) {
                return service.getAlgorithm();
            }
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
            if ( provider != null ) return getCipher(transformation, provider);
        }
        catch (NoSuchAlgorithmException e) { }
        catch (NoSuchPaddingException e) { }
        return Cipher.getInstance(transformation);
    }

    static Cipher getCipher(final String transformation, final Provider provider)
        throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance(transformation, provider);
    }



    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static Signature getSignature(final String algorithm) throws NoSuchAlgorithmException {
        try {
            final Provider provider = getSecurityProvider();
            if ( provider != null ) return getSignature(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) { }
        return Signature.getInstance(algorithm);
    }

    @SuppressWarnings("unchecked")
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
        if ( provider != null ) {
            mac = getMac(algorithm, provider, true);
        }
        if ( mac == null ) mac = Mac.getInstance(algorithm);
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

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static KeyGenerator getKeyGenerator(final String algorithm) throws NoSuchAlgorithmException {
        try {
            final Provider provider = getSecurityProvider();
            if ( provider != null ) return getKeyGenerator(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) { }
        catch (SecurityException e) { debugStackTrace(e); }
        return KeyGenerator.getInstance(algorithm);
    }

    static KeyGenerator getKeyGenerator(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return KeyGenerator.getInstance(algorithm, provider);
    }

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static KeyAgreement getKeyAgreement(final String algorithm) throws NoSuchAlgorithmException {
        try {
            final Provider provider = getSecurityProvider();
            if ( provider != null ) return getKeyAgreement(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) { }
        catch (SecurityException e) { debugStackTrace(e); }
        return KeyAgreement.getInstance(algorithm);
    }

    static KeyAgreement getKeyAgreement(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return KeyAgreement.getInstance(algorithm, provider);
    }

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static SecretKeyFactory getSecretKeyFactory(final String algorithm) throws NoSuchAlgorithmException {
        try {
            final Provider provider = getSecurityProvider();
            if ( provider != null ) return getSecretKeyFactory(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) { }
        catch (SecurityException e) { debugStackTrace(e); }
        return SecretKeyFactory.getInstance(algorithm);
    }

    static SecretKeyFactory getSecretKeyFactory(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return SecretKeyFactory.getInstance(algorithm, provider);
    }

    private static final String providerSSLContext; // NOTE: experimental support for using BCJSSE
    static {
        String providerSSL = SafePropertyAccessor.getProperty("jruby.openssl.ssl.provider", "");
        switch (providerSSL.trim()) {
            case "BC": case "true":
                providerSSL = "BCJSSE"; break;
            case "":  case "false":
                providerSSL = null; break;
        }
        providerSSLContext = providerSSL;
    }

    public static SSLContext getSSLContext(final String protocol)
        throws NoSuchAlgorithmException {
        try {
            if ( providerSSLContext != null && ! "SSL".equals(protocol) ) { // only TLS supported in BCJSSE
                final Provider provider = getJsseProvider(providerSSLContext);
                if ( provider != null ) {
                    return getSSLContext(protocol, provider);
                }
            }
        }
        catch (NoSuchAlgorithmException e) { }
        return SSLContext.getInstance(protocol); // built-in SunJSSE provider on HotSpot
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
