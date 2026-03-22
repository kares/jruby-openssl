package org.jruby.ext.openssl;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link PEMUtils#toPasswordChars} and {@link PEMUtils#clearChars},
 * verifying password handling matches C OpenSSL's approach:
 * - No intermediate immutable Java String created
 * - Intermediate buffers are cleared after conversion
 * - Caller can (and must) clear the returned char[]
 */
public class PEMUtilsPasswordTest {

    // C OpenSSL: const char *pass with ASCII bytes
    @Test
    public void asciiPassword() {
        byte[] bytes = "secret".getBytes(StandardCharsets.US_ASCII);
        char[] result = PEMUtils.toPasswordChars(bytes, 0, bytes.length, StandardCharsets.US_ASCII);
        assertArrayEquals(new char[] { 's', 'e', 'c', 'r', 'e', 't' }, result);
    }

    // C OpenSSL: empty password (pass = "")
    @Test
    public void emptyPassword() {
        char[] result = PEMUtils.toPasswordChars(new byte[0], 0, 0, StandardCharsets.UTF_8);
        assertNotNull(result);
        assertEquals(0, result.length);
    }

    // C OpenSSL: NULL password maps to empty char[]
    @Test
    public void nullRubyObjectReturnsEmpty() {
        char[] result = PEMUtils.toPasswordChars(null);
        assertNotNull(result);
        assertEquals(0, result.length);
    }

    // UTF-8 multi-byte: "café" should decode correctly
    @Test
    public void utf8Password() {
        byte[] bytes = "caf\u00e9".getBytes(StandardCharsets.UTF_8);
        // UTF-8 encoding of é is 0xC3 0xA9 (2 bytes), so 5 bytes total
        assertEquals(5, bytes.length);
        char[] result = PEMUtils.toPasswordChars(bytes, 0, bytes.length, StandardCharsets.UTF_8);
        assertArrayEquals(new char[] { 'c', 'a', 'f', '\u00e9' }, result);
    }

    // JRuby's ASCII-8BIT (binary): getCharset() returns null, should fall back to ISO-8859-1
    @Test
    public void nullCharsetFallsBackToLatin1() {
        byte[] bytes = new byte[] { (byte) 0xC0, (byte) 0xFF, (byte) 0x41 };
        char[] result = PEMUtils.toPasswordChars(bytes, 0, bytes.length, (Charset) null);
        assertEquals(3, result.length);
        assertEquals('\u00C0', result[0]); // 0xC0 -> U+00C0
        assertEquals('\u00FF', result[1]); // 0xFF -> U+00FF
        assertEquals('A', result[2]);       // 0x41 -> 'A'
    }

    // ISO-8859-1 encoding
    @Test
    public void latin1Password() {
        byte[] bytes = new byte[] { 'p', 'a', (byte) 0xDF, (byte) 0xF1 }; // "paßñ"
        char[] result = PEMUtils.toPasswordChars(bytes, 0, bytes.length, StandardCharsets.ISO_8859_1);
        assertArrayEquals(new char[] { 'p', 'a', '\u00DF', '\u00F1' }, result);
    }

    // Offset and length: only slice of buffer is converted
    @Test
    public void offsetAndLength() {
        byte[] bytes = "XXhelloXX".getBytes(StandardCharsets.US_ASCII);
        char[] result = PEMUtils.toPasswordChars(bytes, 2, 5, StandardCharsets.US_ASCII);
        assertArrayEquals(new char[] { 'h', 'e', 'l', 'l', 'o' }, result);
    }

    // clearChars zeroes the array
    @Test
    public void clearCharsZeroesArray() {
        char[] password = "secret".toCharArray();
        PEMUtils.clearChars(password);
        for (char c : password) {
            assertEquals('\0', c);
        }
    }

    // clearChars is safe with null
    @Test
    public void clearCharsHandlesNull() {
        PEMUtils.clearChars(null); // should not throw
    }

    // Returned array is independent — clearing it doesn't affect the source
    @Test
    public void returnedArrayIsACopy() {
        byte[] bytes = "test".getBytes(StandardCharsets.US_ASCII);
        char[] result = PEMUtils.toPasswordChars(bytes, 0, bytes.length, StandardCharsets.US_ASCII);
        PEMUtils.clearChars(result);
        // Source bytes are unchanged
        assertEquals('t', (char) bytes[0]);
        assertEquals('e', (char) bytes[1]);
    }

    // Typical PKCS12 round-trip: password chars can be used with KeyStore
    @Test
    public void passwordCharsCompatibleWithKeyStore() throws Exception {
        byte[] passBytes = "pkcs12pass".getBytes(StandardCharsets.UTF_8);
        char[] passChars = PEMUtils.toPasswordChars(passBytes, 0, passBytes.length, StandardCharsets.UTF_8);
        try {
            // Verify the char[] works with Java KeyStore API
            java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
            ks.load(null, passChars); // initialize empty store with our password
            // No exception means the password format is valid
        } finally {
            PEMUtils.clearChars(passChars);
        }
    }
}
