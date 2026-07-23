
package org.jruby.ext.openssl.x509store;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import org.jruby.ext.openssl.FipsTestSupport;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author kares
 */
public class NameTest {

    @BeforeAll
    public static void notFipsMode() {
        FipsTestSupport.setFipsMode(false, true);
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

    @Test
    public void hashNonAsciiCanonMatchesOpenSSL() {
        // OpenSSL subject_hash(/CN=Éé Test) [UTF8String] == aef52d11 (OpenSSL 3.5)
        assertEquals(0xaef52d11L, new Name(cn("\u00C9\u00E9 Test")).hash());
        // non-ASCII uppercase must NOT be case-folded (asn1_string_canon lower-cases only A-Z)
        assertNotEquals(new Name(cn("\u00C9")).hash(), new Name(cn("\u00E9")).hash()); // É vs é
        assertEquals(new Name(cn("A")).hash(), new Name(cn("a")).hash()); // ASCII case still folds
    }

    private static X500Name cn(final String cn) {
        return new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, cn).build();
    }
}
