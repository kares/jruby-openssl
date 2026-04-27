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

public final class PKeyShim {

    private PKeyShim() {}

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
