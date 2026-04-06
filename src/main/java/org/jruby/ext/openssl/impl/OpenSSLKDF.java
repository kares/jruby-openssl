package org.jruby.ext.openssl.impl;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Helper for specific legacy behavior: OpenSSL's EVP_BytesToKey password-to-key
 * derivation used by (old) PEM encryption formats like DEK-Info
 */
public abstract class OpenSSLKDF {

    public static byte[] evpBytesToKey(final char[] password, final byte[] salt, final int keyLength) {
        final byte[] passwordBytes = charsToBytes(password);
        try {
            final MessageDigest md5 = MessageDigest.getInstance("MD5");
            final byte[] key = new byte[keyLength];
            byte[] digest = null;
            int offset = 0;

            while (offset < keyLength) {
                md5.reset();
                if (digest != null) md5.update(digest);
                md5.update(passwordBytes);
                md5.update(salt, 0, Math.min(8, salt.length));
                digest = md5.digest();

                final int len = Math.min(digest.length, keyLength - offset);
                System.arraycopy(digest, 0, key, offset, len);
                offset += len;
            }

            return key;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 digest not available", e);
        } finally {
            Arrays.fill(passwordBytes, (byte) 0);
        }
    }

    private static byte[] charsToBytes(final char[] password) {
        final byte[] bytes = new byte[password.length];
        for (int i = 0; i < password.length; i++) {
            bytes[i] = (byte) password[i];
        }
        return bytes;
    }
}
