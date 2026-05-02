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
package org.jruby.ext.openssl.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Reader;
import java.security.GeneralSecurityException;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collection;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.openssl.PEMDecryptor;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;

import org.jruby.ext.openssl.SecurityHelper;
import org.jruby.ext.openssl.impl.OpenSSLKDF;

import static org.jruby.ext.openssl.x509store.PEMInputOutput.getKeyFactory;

/**
 * PEM Utilities, mostly to replace <code>PEMHandler</code>.
 *
 * @author kares
 */
public abstract class PEMGenerator {

    public static byte[] generatePKCS12(final Reader keyReader, final byte[] cert,
        final String aliasName, final char[] password)
        throws IOException, GeneralSecurityException {

        final Collection<? extends Certificate> certChain =
            SecurityHelper.getCertificateFactory("X.509").generateCertificates(new ByteArrayInputStream(cert));

        final PEMKeyPair pemKeyPair = readInternal(keyReader, null);
        final KeyFactory keyFactory = getKeyFactory( pemKeyPair.getPrivateKeyInfo().getPrivateKeyAlgorithm() );
        Key privateKey = keyFactory.generatePrivate( new PKCS8EncodedKeySpec( pemKeyPair.getPrivateKeyInfo().getEncoded() ) );

        final KeyStore keyStore = SecurityHelper.getKeyStore("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry( aliasName, privateKey, null, certChain.toArray(new Certificate[certChain.size()]) );

        final ByteArrayOutputStream pkcs12Out = new ByteArrayOutputStream();
        keyStore.store(pkcs12Out, password == null ? new char[0] : password);

        return pkcs12Out.toByteArray();
    }

    static PEMKeyPair readInternal(final Reader reader, final char[] password) throws IOException {
        Object keyPair = new PEMParser(reader).readObject();
        if ( keyPair instanceof PEMEncryptedKeyPair) {
            return ((PEMEncryptedKeyPair) keyPair).decryptKeyPair(new PEMDecryptorImpl(password));
        }
        return (PEMKeyPair) keyPair;
    }

    private static class PEMDecryptorImpl implements PEMDecryptorProvider, PEMDecryptor {

        PEMDecryptorImpl(char[] password) { this.password = password; }

        private char[] password;
        private String dekAlgName;

        public PEMDecryptor get(String dekAlgName) {
            this.dekAlgName = dekAlgName;
            return this; // PEMDecryptor
        }

        public byte[] decrypt(byte[] keyBytes, byte[] iv) throws PEMException {
            return decrypt(keyBytes, password, dekAlgName, iv);
        }

        static byte[] decrypt(
            byte[] bytes,
            char[] password,
            String dekAlgName,
            byte[] iv)
            throws PEMException
        {
            AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
            String alg;
            String blockMode = "CBC";
            String padding = "PKCS5Padding";
            Key sKey;

            // Figure out block mode and padding.
            if (dekAlgName.endsWith("-CFB"))
            {
                blockMode = "CFB";
                padding = "NoPadding";
            }
            if (dekAlgName.endsWith("-ECB") ||
                "DES-EDE".equals(dekAlgName) ||
                "DES-EDE3".equals(dekAlgName))
            {
                // ECB is actually the default (though seldom used) when OpenSSL
                // uses DES-EDE (des2) or DES-EDE3 (des3).
                blockMode = "ECB";
                paramSpec = null;
            }
            if (dekAlgName.endsWith("-OFB"))
            {
                blockMode = "OFB";
                padding = "NoPadding";
            }


            // Figure out algorithm and key size.
            if (dekAlgName.startsWith("DES-EDE"))
            {
                alg = "DESede";
                // "DES-EDE" is actually des2 in OpenSSL-speak!
                // "DES-EDE3" is des3.
                boolean des2 = !dekAlgName.startsWith("DES-EDE3");
                sKey = secretKeySpec(password, alg, 24, iv, des2);
            }
            else if (dekAlgName.startsWith("DES-"))
            {
                alg = "DES";
                sKey = secretKeySpec(password, alg, 8, iv);
            }
            else if (dekAlgName.startsWith("BF-"))
            {
                alg = "Blowfish";
                sKey = secretKeySpec(password, alg, 16, iv);
            }
            else if (dekAlgName.startsWith("RC2-"))
            {
                alg = "RC2";
                int keyBits = 128;
                if (dekAlgName.startsWith("RC2-40-"))
                {
                    keyBits = 40;
                }
                else if (dekAlgName.startsWith("RC2-64-"))
                {
                    keyBits = 64;
                }
                sKey = secretKeySpec(password, alg, keyBits / 8, iv);
                if (paramSpec == null) // ECB block mode
                {
                    paramSpec = new RC2ParameterSpec(keyBits);
                }
                else
                {
                    paramSpec = new RC2ParameterSpec(keyBits, iv);
                }
            }
            else if (dekAlgName.startsWith("AES-"))
            {
                alg = "AES";
                byte[] salt = iv;
                if (salt.length > 8)
                {
                    salt = new byte[8];
                    System.arraycopy(iv, 0, salt, 0, 8);
                }

                int keyBits;
                if (dekAlgName.startsWith("AES-128-"))
                {
                    keyBits = 128;
                }
                else if (dekAlgName.startsWith("AES-192-"))
                {
                    keyBits = 192;
                }
                else if (dekAlgName.startsWith("AES-256-"))
                {
                    keyBits = 256;
                }
                else
                {
                    throw new PEMException("unknown AES encryption with private key");
                }
                sKey = secretKeySpec(password, "AES", keyBits / 8, salt);
            }
            else
            {
                throw new PEMException("unknown encryption with private key");
            }

            String transformation = alg + '/' + blockMode + '/' + padding;

            try
            {
                javax.crypto.Cipher cipher = SecurityHelper.getCipher(transformation);
                final int decryptMode = javax.crypto.Cipher.DECRYPT_MODE;

                if (paramSpec == null) // ECB block mode
                {
                    cipher.init(decryptMode, sKey);
                }
                else
                {
                    cipher.init(decryptMode, sKey, paramSpec);
                }
                return cipher.doFinal(bytes);
            }
            catch (Exception e)
            {
                throw new PEMException("exception using cipher - please check password and data.", e);
            }
        }

        private static SecretKey secretKeySpec(
            char[] password,
            String algorithm,
            int keyLength,
            byte[] salt) {
            return secretKeySpec(password, algorithm, keyLength, salt, false);
        }

        private static SecretKey secretKeySpec(
            char[] password,
            String algorithm,
            int keyLength,
            byte[] salt,
            boolean des2) {
            byte[] key = OpenSSLKDF.evpBytesToKey(password, salt, keyLength);
            if (des2 && key.length >= 24) {
                // For DES2, we must copy first 8 bytes into the last 8 bytes.
                System.arraycopy(key, 0, key, 16, 8);
            }
            return new SecretKeySpec(key, algorithm);
        }

    }

}
