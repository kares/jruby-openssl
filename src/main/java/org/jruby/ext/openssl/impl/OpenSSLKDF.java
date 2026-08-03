/*
 * The MIT License
 *
 * Copyright (C) 2026 Karol Bucek
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
package org.jruby.ext.openssl.impl;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.jruby.ext.openssl.SecurityHelper;
import java.util.Arrays;

/**
 * Helper for specific legacy behavior: OpenSSL's EVP_BytesToKey password-to-key
 * derivation used by (old) PEM encryption formats like DEK-Info
 */
public abstract class OpenSSLKDF {

    /**
     * @throws NoSuchAlgorithmException when MD5 is not available (under FIPS)
     */
    public static byte[] evpBytesToKey(final char[] password, final byte[] salt, final int keyLength)
        throws NoSuchAlgorithmException {
        final byte[] passwordBytes = charsToBytes(password);
        try {
            final MessageDigest md5 = SecurityHelper.getMessageDigest("MD5");
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
