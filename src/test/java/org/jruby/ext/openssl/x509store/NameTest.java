
package org.jruby.ext.openssl.x509store;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import org.jruby.ext.openssl.SecurityHelperTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author kares
 */
public class NameTest {

    @BeforeAll
    public static void notFipsMode() {
        SecurityHelperTest.setFipsMode(false, true);
    }

    @Test
    public void hashMatchesOpenSSLCanonicalForm() {
        // OpenSSL X509_NAME_hash(/CN=Test CA) == 3387b84d (verified against MRI / OpenSSL 3.5.4)
        assertEquals(0x3387b84dL, new Name(cn("Test CA")).hash());
    }

    @Test
    public void hashIsCaseAndWhitespaceInsensitive() {
        final long h = new Name(cn("test ca")).hash();
        assertEquals(h, new Name(cn("Test CA")).hash());
        assertEquals(h, new Name(cn("Test  CA")).hash()); // collapsed internal whitespace
        assertEquals(h, new Name(cn("  Test CA  ")).hash()); // trimmed
    }

    private static X500Name cn(final String cn) {
        return new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, cn).build();
    }
}
