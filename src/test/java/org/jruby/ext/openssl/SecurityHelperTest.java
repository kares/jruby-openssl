
package org.jruby.ext.openssl;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author kares
 */
public class SecurityHelperTest {

    @BeforeAll
    public static void setFipsMode() {
        resetProvidersState();
        SecurityHelper.setFipsMode(false);
    }

    @AfterAll
    public static void resetProvidersState() {
        Security.removeProvider("BC");
        Security.removeProvider("BCFIPS");
        Security.removeProvider("BCJSSE");
        SecurityHelper.securityProvider = null;
        SecurityHelper.initSecurityProvider = true;
        SecurityHelper.jsseProvider = null;
        SecurityHelper.initJsseProvider = true;
        SecurityHelper.registerProvider = null;
    }

    @AfterEach
    public void resetState() {
        resetProvidersState();
    }

    public void disableSecurityProvider() {
        SecurityHelper.securityProvider = null;
        SecurityHelper.initSecurityProvider = false;
    }

    @Test
    public void usesBouncyCastleSecurityProviderByDefault() {
        assertNotNull(SecurityHelper.getSecurityProvider());
        assertEquals("org.bouncycastle.jce.provider.BouncyCastleProvider",
            SecurityHelper.getSecurityProvider().getClass().getName()
        );
    }

    @Test
    public void allowsToSetSecurityProvider() {
        final Provider provider = new DummyProvider();
        SecurityHelper.setSecurityProvider(provider);

        assertSame(provider, SecurityHelper.getSecurityProvider());
    }

    public final class DummyProvider extends Provider {
        public DummyProvider() {
            super("DUMMY", 1.0, SecurityHelperTest.this.toString());
        }
    }

    @Test
    public void doesNotRegisterBouncyCastleSecurityProviderByDefault() {
        SecurityHelper.getSecurityProvider();
        assertNotNull(SecurityHelper.securityProvider);
        assertNull(java.security.Security.getProvider(getProviderName()));
    }

    @Test
    public void registersSecurityProviderWhenRequested() {
        SecurityHelper.setRegisterProvider(true);
        try {
            SecurityHelper.getSecurityProvider();
            assertNotNull(SecurityHelper.securityProvider);
            assertNotNull(java.security.Security.getProvider(getProviderName()));
        }
        finally {
            java.security.Security.removeProvider("BC");
            SecurityHelper.setRegisterProvider(false);
        }
    }

    @Test
    public void attemptsSecurityProviderRegistration() {
        final String register = System.getProperty("jruby.openssl.provider.register");
        System.setProperty("jruby.openssl.provider.register", "true");
        assertNull(SecurityHelper.securityProvider);
        try {
            SecurityHelper.checkAndRegisterProviderOnce();
            assertNotNull(SecurityHelper.getSecurityProvider()); // trigger
            assertNotNull(SecurityHelper.securityProvider);
            assertTrue(isProviderRegistered());
        }
        finally {
            java.security.Security.removeProvider(getProviderName());
            SecurityHelper.setRegisterProvider(false);
            if (register == null) {
                System.clearProperty("jruby.openssl.provider.register");
            } else {
                System.setProperty("jruby.openssl.provider.register", register);
            }
        }
    }

    @Test
    public void registersSecurityProviderRegistrationWhenInitialized() {
        SecurityHelper.getSecurityProvider(); // BC provider initialized

        final String register = System.getProperty("jruby.openssl.provider.register");
        System.setProperty("jruby.openssl.provider.register", "true");
        try {
            SecurityHelper.setRegisterProvider(true);
            assertTrue(isProviderRegistered());
        }
        finally {
            java.security.Security.removeProvider(getProviderName());
            SecurityHelper.setRegisterProvider(false);
            if (register == null) {
                System.clearProperty("jruby.openssl.provider.register");
            } else {
                System.setProperty("jruby.openssl.provider.register", register);
            }
        }
    }

    // Standart java.security

    @Test
    public void testGetKeyFactory() throws Exception {
        assertNotNull( SecurityHelper.getKeyFactory("RSA") );
        assertNotNull( SecurityHelper.getKeyFactory("DSA") );
    }

    @Test
    public void testGetKeyFactoryWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getKeyFactory("RSA") );
        assertNotNull( SecurityHelper.getKeyFactory("DSA") );
    }

    @Test
    public void testGetKeyFactoryThrows() throws Exception {
        try {
            SecurityHelper.getKeyFactory("USA");
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
        try {
            SecurityHelper.getKeyFactory("USA", getProvider());
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
    }

    //

    @Test
    public void testGetKeyPairGenerator() throws Exception {
        assertNotNull( SecurityHelper.getKeyPairGenerator("RSA") );
        assertNotNull( SecurityHelper.getKeyPairGenerator("DSA") );

        assertNotNull( SecurityHelper.getKeyPairGenerator("RSA", getProvider()) );
    }

    @Test
    public void testGetKeyPairGeneratorWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getKeyPairGenerator("RSA") );
        assertNotNull( SecurityHelper.getKeyPairGenerator("DSA") );
    }

    @Test
    public void testGetKeyPairGeneratorThrows() throws Exception {
        try {
            SecurityHelper.getKeyPairGenerator("USA");
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
        try {
            SecurityHelper.getKeyPairGenerator("USA", getProvider());
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
    }

    @Test
    public void testGetKeyStore() throws Exception {
        assertNotNull( SecurityHelper.getKeyStore("PKCS12") );

        assertNotNull( SecurityHelper.getKeyStore("PKCS12", getProvider()) );
    }

    @Test
    public void testGetKeyStoreWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getKeyStore("PKCS12") );
    }

    @Test
    public void testGetKeyStoreThrows() throws Exception {
        try {
            SecurityHelper.getKeyStore("PKCS42");
            fail();
        }
        catch (KeyStoreException e) {
            // OK
        }
        try {
            SecurityHelper.getKeyStore("PKCS42", getProvider());
            fail();
        }
        catch (KeyStoreException e) {
            // OK
        }
    }

    @Test
    public void testGetMessageDigest() throws Exception {
        assertNotNull( SecurityHelper.getMessageDigest("MD5") );
        assertNotNull( SecurityHelper.getMessageDigest("SHA-1") );

        assertNotNull( SecurityHelper.getMessageDigest("MD5", getProvider()) );
    }

    @Test
    public void testGetMessageDigestWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getMessageDigest("MD5") );
        assertNotNull( SecurityHelper.getMessageDigest("SHA-1") );
    }

    @Test
    public void testGetMessageDigestThrows() throws Exception {
        try {
            SecurityHelper.getMessageDigest("XXL");
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
        try {
            SecurityHelper.getMessageDigest("XXL", getProvider());
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
    }

    @Test
    public void testGetSignature() throws Exception {
        assertNotNull( SecurityHelper.getSignature("NONEwithRSA") );

        assertNotNull( SecurityHelper.getSignature("NONEwithRSA", getProvider()) );
    }

    @Test
    public void testGetSignatureWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getSignature("NONEwithRSA") );
    }

    @Test
    public void testGetSignatureThrows() throws Exception {
        try {
            SecurityHelper.getSignature("SOMEwithRSA");
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
        try {
            SecurityHelper.getSignature("SOMEwithRSA", getProvider());
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
    }

    @Test
    public void testGetCertificateFactory() throws Exception {
        assertNotNull( SecurityHelper.getCertificateFactory("X.509") );

        assertNotNull( SecurityHelper.getCertificateFactory("X.509", getProvider()) );
    }

    @Test
    public void testGetCertificateFactoryWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getCertificateFactory("X.509") );
    }

    @Test
    public void testGetCertificateFactoryThrows() throws Exception {
        try {
            SecurityHelper.getCertificateFactory("X.510");
            fail();
        }
        catch (CertificateException e) {
            // OK
        }
        try {
            SecurityHelper.getCertificateFactory("X.510", getProvider());
            fail();
        }
        catch (CertificateException e) {
            // OK
        }
    }

    @Test
    public void testGetSecureRandom() throws Exception {
        assertNotNull( SecurityHelper.getSecureRandom() );
    }

    // JCE

    @Test
    public void testGetCipher() throws Exception {
        assertNotNull( SecurityHelper.getCipher("DES") );
        assertNotNull( SecurityHelper.getCipher("AES") );

        assertNotNull( SecurityHelper.getCipher("DES/CBC/PKCS5Padding") );
    }

    @Test
    public void testGetCipherBC() throws Exception {
        assertNotNull( SecurityHelper.getCipher("AES", getProvider()) );

        assertNotNull( SecurityHelper.getCipher("DES/CBC/PKCS5Padding", getProvider()) );
    }

    @Test
    public void testGetCipherWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getCipher("DES") );
        assertNotNull( SecurityHelper.getCipher("AES") );
    }

    @Test
    public void testGetSecretKeyFactory() throws Exception {
        assertNotNull( SecurityHelper.getSecretKeyFactory("DES") );

        assertNotNull( SecurityHelper.getSecretKeyFactory("DESede", getProvider()) );
    }

    @Test
    public void testGetSecretKeyFactoryWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getSecretKeyFactory("DES") );
        assertNotNull( SecurityHelper.getSecretKeyFactory("DESede") );
    }

    @Test
    public void testGetSecretKeyFactoryThrows() throws Exception {
        try {
            SecurityHelper.getSecretKeyFactory("MESS");
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
        try {
            SecurityHelper.getSecretKeyFactory("MESS", getProvider());
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
    }

    @Test
    public void testGetMac() throws Exception {
        assertNotNull( SecurityHelper.getMac("HmacMD5") );
        assertNotNull( SecurityHelper.getMac("HmacSHA1") );

        assertNotNull( SecurityHelper.getMac("HmacMD5", getProvider()) );
    }

    @Test
    public void testGetMacWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getMac("HMacMD5") );
    }

    @Test
    public void testGetMacThrows() throws Exception {
        try {
            SecurityHelper.getMac("HmacMDX");
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
        try {
            SecurityHelper.getMac("HmacMDX", getProvider());
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
    }

    @Test
    public void testGetKeyGenerator() throws Exception {
        assertNotNull( SecurityHelper.getKeyGenerator("AES") );

        assertNotNull( SecurityHelper.getKeyGenerator("AES", getProvider()) );
    }

    @Test
    public void testGetKeyGeneratorWithoutBC() throws Exception {
        disableSecurityProvider();
        assertNotNull( SecurityHelper.getKeyGenerator("AES") );
    }

    @Test
    public void testGetKeyGeneratorThrows() throws Exception {
        try {
            SecurityHelper.getKeyGenerator("AMD");
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
        try {
            SecurityHelper.getKeyGenerator("AMD", getProvider());
            fail();
        }
        catch (NoSuchAlgorithmException e) {
            // OK
        }
    }

    // pre-registered provider detection tests

    @Test
    public void reusesPreRegisteredBCProvider() {
        // simulate BC pre-registered via java.security
        Provider preRegistered = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        Security.addProvider(preRegistered);
        try {
            // SecurityHelper state is clean (resetState in @AfterEach)
            Provider resolved = SecurityHelper.getSecurityProvider();
            assertNotNull(resolved);
            // should be the exact same instance, not a newly created one
            assertSame(preRegistered, resolved, "should reuse the pre-registered BC provider");
        }
        finally {
            Security.removeProvider("BC");
        }
    }

    @Test
    public void createsNewBCProviderWhenNonePreRegistered() {
        // no provider pre-registered (clean state from @AfterEach)
        assertNull(Security.getProvider("BC"));
        assertNull(Security.getProvider("BCFIPS"));

        Provider resolved = SecurityHelper.getSecurityProvider();
        assertNotNull(resolved);
        assertEquals("BC", resolved.getName());
        // should NOT be globally registered (default registerProvider is false)
        assertNull(Security.getProvider("BC"));
    }

    @Test
    public void reusesPreRegisteredBCJSSEProvider() {
        // simulate BCJSSE pre-registered via java.security
        Provider bcProv = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        Provider preRegisteredJsse = new org.bouncycastle.jsse.provider.BouncyCastleJsseProvider(bcProv);
        Security.addProvider(preRegisteredJsse);
        try {
            Provider resolved = SecurityHelper.getJsseProvider();
            assertNotNull(resolved);
            assertSame(preRegisteredJsse, resolved, "should reuse pre-registered BCJSSE provider");
        }
        finally {
            Security.removeProvider("BCJSSE");
        }
    }

    @Test
    public void createsBCJSSEWhenNonePreRegistered() {
        assertNull(Security.getProvider("BCJSSE"));

        Provider resolved = SecurityHelper.getJsseProvider();
        assertNotNull(resolved);
        assertEquals("BCJSSE", resolved.getName());
        // should NOT be globally registered
        assertNull(Security.getProvider("BCJSSE"));
    }

    @Test
    public void testCertificateFactoryProviderStaysConstant() throws Exception {
        Provider[] registeredProviders = Security.getProviders();

        try {
            // clear previous providers
            for (Provider provider : registeredProviders) Security.removeProvider(provider.getName());

            CertificateFactory certFactory1 = SecurityHelper.getCertificateFactory("X.509");
            CertificateFactory certFactory2 = SecurityHelper.getCertificateFactory("X.509");

            assertSame(certFactory1.getProvider(), certFactory2.getProvider());
        } finally {
            // clear any added by the test
            for (Provider provider : Security.getProviders()) Security.removeProvider(provider.getName());

            // restore previous providers
            for (Provider provider : registeredProviders) Security.addProvider(provider);
        }
    }

    private static Provider getProvider() {
        return SecurityHelper.getSecurityProvider();
    }

    private static String getProviderName() {
        return SecurityHelper.securityProvider.getName();
    }

    private static boolean isProviderRegistered() {
        if (SecurityHelper.securityProvider == null) return false;
        return Security.getProvider(getProviderName()) != null;
    }
}
