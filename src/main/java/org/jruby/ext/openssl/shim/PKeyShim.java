/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Karol Bucek
 */
package org.jruby.ext.openssl.shim;

import java.security.PublicKey;

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

public abstract class PKeyShim {

    /** extract raw point encoding from an EdDSA public key */
    public static byte[] getEdDSAPointEncoding(PublicKey key) {
        return ((EdDSAPublicKey) key).getPointEncoding();
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
