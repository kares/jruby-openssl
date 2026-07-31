/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Karol Bucek
 */
package org.jruby.ext.openssl.shim;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import org.jruby.ext.openssl.PKeyRSA;
import org.jruby.ext.openssl.SecurityHelper;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;

public abstract class PKeyShim {

    /**
     * Recover the actual PSS salt length used to produce a signature; -1 when undeterminable.
     * <p>
     * regular BC: unwrap the signature with the raw RSA primitive (RSA/ECB/NoPadding) and
     * parse the PSS-encoded message (dataBytes is unused on this path).
     */
    public static int autoPSSSaltLength(RSAPublicKey pubKey,
                                        byte[] dataBytes, byte[] sigBytes,
                                        String digestAlg, String mgf1Alg) {
        final byte[] raw;
        try {
            javax.crypto.Cipher rsa = SecurityHelper.getCipher("RSA/ECB/NoPadding");
            rsa.init(javax.crypto.Cipher.DECRYPT_MODE, pubKey);
            raw = rsa.doFinal(sigBytes);
        }
        catch (GeneralSecurityException e) {
            return -1;
        }

        // emLen = ceil((modBits - 1) / 8) per RFC 8017 §9.1.1
        int emLen = (pubKey.getModulus().bitLength() - 1 + 7) / 8;

        // raw RSA output may be shorter than emLen if leading bytes are zero; left-pad to emLen
        byte[] em;
        if (raw.length < emLen) {
            em = new byte[emLen];
            System.arraycopy(raw, 0, em, emLen - raw.length, raw.length);
        } else {
            em = raw;
        }

        int hLen = PKeyRSA.getDigestLength(digestAlg);
        if (emLen < hLen + 2 || em[emLen - 1] != (byte) 0xBC) return -1;

        int dbLen = emLen - hLen - 1;
        byte[] H = new byte[hLen];
        System.arraycopy(em, dbLen, H, 0, hLen);

        // recover DB = MGF1(H, dbLen) XOR maskedDB
        byte[] DB = new byte[dbLen];
        System.arraycopy(em, 0, DB, 0, dbLen);
        final byte[] mask;
        try {
            mask = PKeyRSA.mgf1(H, dbLen, mgf1Alg);
        }
        catch (NoSuchAlgorithmException e) {
            return -1;
        }
        for (int i = 0; i < dbLen; i++) {
            DB[i] ^= mask[i];
        }

        // clear top bits per RFC 8017 §9.1.2
        int topBits = 8 * emLen - (pubKey.getModulus().bitLength() - 1);
        if (topBits > 0) DB[0] &= (byte)(0xFF >>> topBits);

        // find the 0x01 separator; salt follows it
        for (int i = 0; i < dbLen; i++) {
            if (DB[i] == 0x01) return dbLen - i - 1;
            if (DB[i] != 0x00) return -1;
        }
        return -1;
    }

    /** extract raw point encoding from an EdDSA public key */
    public static byte[] getEdDSAPointEncoding(PublicKey key) {
        return ((EdDSAPublicKey) key).getPointEncoding();
    }

    /** extract the raw u-coordinate from an XDH public key */
    public static byte[] getXDHUEncoding(PublicKey key) {
        return ((XDHPublicKey) key).getUEncoding();
    }

    /** get the EC parameters ASN.1 object from an ECPrivateKey structure */
    public static ASN1Primitive getECParametersObject(org.bouncycastle.asn1.sec.ECPrivateKey key) {
        return key.getParametersObject().toASN1Primitive();
    }

    /**
     * Get the public key bit string from an ECPrivateKey structure.
     *
     * @implNote regular BC returns ASN1BitString; bc-fips returns DERBitString;
     * Both are functionally equivalent (DERBitString IS-A ASN1BitString in BC),
     * but the JVM method descriptor differs so we shim it for compile safety.
     */
    public static ASN1BitString getECPublicKey(org.bouncycastle.asn1.sec.ECPrivateKey key) {
        return key.getPublicKey();
    }

    /** create an ECPrivateKey with public key data */
    public static org.bouncycastle.asn1.sec.ECPrivateKey newECPrivateKey(
            int orderBitLength, java.math.BigInteger s,
            ASN1BitString publicKeyData, ASN1Encodable parameters) {
        return new org.bouncycastle.asn1.sec.ECPrivateKey(
                orderBitLength, s, publicKeyData, parameters);
    }

    /** create a CertificationRequest from components */
    public static CertificationRequest newCertificationRequest(
            CertificationRequestInfo reqInfo, AlgorithmIdentifier algId,
            DERBitString signature) {
        return new CertificationRequest(reqInfo, algId, signature);
    }

    /** construct SubjectPublicKeyInfo from an ASN1Sequence */
    public static SubjectPublicKeyInfo newSubjectPublicKeyInfo(ASN1Sequence seq) {
        return new SubjectPublicKeyInfo(seq);
    }

    /**
     * @implNote regular BC returns ASN1BitString; bc-fips returns DERBitString
     */
    public static DERBitString getCertReqSignature(CertificationRequest req) {
        // BC returns ASN1BitString which in practice is always a DERBitString
        return (DERBitString) req.getSignature();
    }
}
