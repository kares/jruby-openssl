/*
 * Copyright (c) 2026 Karol Bucek.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.jruby.ext.openssl;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.XDHPrivateKey;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.openssl.log.Logger;
import org.jruby.ext.openssl.shim.PKeyShim;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

import static org.jruby.ext.openssl.util.RubySupport.newString;

/**
 * Wraps XDH keys (X25519, X448) - key agreement only, they can not sign.
 *
 * Not exposed — instances appear as OpenSSL::PKey::PKey.
 */
public class PKeyXDH extends PKey {

    private static final Logger LOG = Logger.getLogger(PKeyXDH.class);

    private PublicKey publicKey;
    private PrivateKey privateKey;

    private PKeyXDH(Ruby runtime, RubyClass type, PublicKey publicKey, PrivateKey privateKey) {
        super(runtime, type);
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    PKeyXDH(Ruby runtime, PublicKey publicKey, PrivateKey privateKey) {
        this(runtime, PKey._PKey(runtime).getClass("PKey"), publicKey, privateKey);
    }

    PKeyXDH(Ruby runtime, PublicKey publicKey) {
        this(runtime, publicKey, null);
    }

    static PKeyXDH newInstance(final Ruby runtime, final KeyPair keyPair) {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        if (publicKey == null && privateKey instanceof XDHPrivateKey) {
            publicKey = ((XDHPrivateKey) privateKey).getPublicKey();
        }
        return new PKeyXDH(runtime, publicKey, privateKey);
    }

    static PKeyXDH generate(final ThreadContext context, final String algorithm) {
        try {
            KeyPairGenerator gen = SecurityHelper.getKeyPairGenerator(normalize(algorithm));
            gen.initialize(keySize(algorithm), OpenSSL.getSecureRandom(context));
            return newInstance(context.runtime, gen.generateKeyPair());
        }
        catch (NoSuchAlgorithmException e) {
            throw newPKeyError(context.runtime, "unsupported algorithm: " + algorithm);
        }
        catch (Exception e) {
            LOG.debugStack(context.runtime, null, e);
            throw newPKeyError(context.runtime, e.getMessage());
        }
    }

    static PKeyXDH fromRawPrivateKey(final Ruby runtime, final String algorithm, final byte[] bytes) {
        try {
            PrivateKeyInfo info = new PrivateKeyInfo(
                new AlgorithmIdentifier(getXDHObjectId(algorithm)), new DEROctetString(bytes));
            KeyFactory keyFactory = SecurityHelper.getKeyFactory(normalize(algorithm));
            PrivateKey privKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(info.getEncoded()));

            PublicKey pubKey = null;
            if (privKey instanceof XDHPrivateKey) {
                pubKey = ((XDHPrivateKey) privKey).getPublicKey();
            }
            return new PKeyXDH(runtime, pubKey, privKey);
        }
        catch (IllegalArgumentException e) {
            throw newPKeyError(runtime, e.getMessage());
        }
        catch (Exception e) {
            LOG.debugStack(runtime, null, e);
            throw newPKeyError(runtime, e.getMessage());
        }
    }

    static PKeyXDH fromRawPublicKey(final Ruby runtime, final String algorithm, final byte[] bytes) {
        try {
            SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(getXDHObjectId(algorithm)), bytes);
            KeyFactory keyFactory = SecurityHelper.getKeyFactory(normalize(algorithm));
            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(pubInfo.getEncoded()));

            return new PKeyXDH(runtime, pubKey);
        }
        catch (IllegalArgumentException e) {
            throw newPKeyError(runtime, e.getMessage());
        }
        catch (Exception e) {
            LOG.debugStack(runtime, null, e);
            throw newPKeyError(runtime, e.getMessage());
        }
    }

    private static ASN1ObjectIdentifier getXDHObjectId(final String algorithm) {
        if ("X25519".equalsIgnoreCase(algorithm)) return EdECObjectIdentifiers.id_X25519;
        if ("X448".equalsIgnoreCase(algorithm)) return EdECObjectIdentifiers.id_X448;
        throw new IllegalArgumentException("unsupported algorithm: " + algorithm);
    }

    private static String normalize(final String algorithm) {
        return "X448".equalsIgnoreCase(algorithm) ? "X448" : "X25519";
    }

    private static int keySize(final String algorithm) { // BC only accepts the curve's own size
        return "X448".equalsIgnoreCase(algorithm) ? 448 : 255;
    }

    @Override
    public PublicKey getPublicKey() { return publicKey; }

    @Override
    public PrivateKey getPrivateKey() { return privateKey; }

    @Override
    public String getAlgorithm() { // BC returns "X25519" or "X448"
        if (privateKey != null) return privateKey.getAlgorithm();
        if (publicKey != null) return publicKey.getAlgorithm();
        return "XDH";
    }

    @Override
    public String getKeyType() { return "XDH"; }

    @Override
    public String getTypeName() { return getAlgorithm().toUpperCase(); }

    @Override
    public RubyString oid() { // MRI: OBJ_nid2sn returns "X25519" or "X448"
        return getRuntime().newString(getAlgorithm().toUpperCase());
    }

    @Override
    public IRubyObject sign(IRubyObject digest, IRubyObject data) {
        throw newPKeyError(getRuntime(), "EVP_DigestSignInit: operation not supported for this keytype");
    }

    @Override
    public IRubyObject verify(IRubyObject digest, IRubyObject sign, IRubyObject data) {
        throw newPKeyError(getRuntime(), "EVP_DigestVerifyInit: operation not supported for this keytype");
    }

    @Override
    @JRubyMethod(name = "derive")
    public IRubyObject derive(ThreadContext context, IRubyObject peer) {
        final Ruby runtime = context.runtime;
        if (privateKey == null) throw newPKeyError(runtime, "EVP_PKEY_derive: missing key");
        if (!(peer instanceof PKey)) {
            throw runtime.newTypeError(peer, _PKey(runtime).getClass("PKey"));
        }
        final PublicKey peerKey = ((PKey) peer).getPublicKey();
        if (peerKey == null) throw newPKeyError(runtime, "EVP_PKEY_derive: missing public key");

        try {
            KeyAgreement agreement = SecurityHelper.getKeyAgreement(getAlgorithm());
            agreement.init(privateKey);
            agreement.doPhase(peerKey, true);
            return newString(runtime, agreement.generateSecret());
        }
        catch (GeneralSecurityException e) {
            throw newPKeyError(runtime, e.getMessage());
        }
    }

    @Override
    @JRubyMethod(name = "raw_private_key")
    public IRubyObject raw_private_key(ThreadContext context) {
        final Ruby runtime = context.runtime;
        if (privateKey == null) throw newPKeyError(runtime, "private key not set");

        try {
            PrivateKeyInfo info = PrivateKeyInfo.getInstance(privateKey.getEncoded());
            ASN1OctetString oct = ASN1OctetString.getInstance(info.parsePrivateKey());
            return newString(runtime, oct.getOctets());
        }
        catch (Exception e) {
            throw newPKeyError(runtime, e);
        }
    }

    @Override
    @JRubyMethod(name = "raw_public_key")
    public IRubyObject raw_public_key(ThreadContext context) {
        final Ruby runtime = context.runtime;
        if (publicKey == null) throw newPKeyError(runtime, "public key not set");
        return newString(runtime, PKeyShim.getXDHUEncoding(publicKey));
    }

    @Override
    public RubyString to_der() {
        final Ruby runtime = getRuntime();
        try {
            if (privateKey != null) return newString(runtime, privateKey.getEncoded());
            if (publicKey != null) return newString(runtime, publicKey.getEncoded());
            throw newPKeyError(runtime, "no key set");
        }
        catch (Exception e) {
            throw newPKeyError(runtime, e);
        }
    }

    @Override
    public RubyString to_pem(ThreadContext context, final IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        try {
            if (privateKey != null) return private_to_pem(context, args);
            if (publicKey != null) return public_to_pem(context);
            throw newPKeyError(runtime, "no key set");
        }
        catch (Exception e) {
            throw newPKeyError(runtime, e.getMessage());
        }
    }

    @Override
    public RubyString to_text() {
        final StringBuilder sb = new StringBuilder();
        sb.append(getAlgorithm().toUpperCase()).append(' ');
        sb.append(privateKey != null ? "Private-Key:\n" : "Public-Key:\n");
        if (publicKey != null) {
            sb.append("pub:\n");
            addSplittedAndFormatted(sb, bytesToHex(PKeyShim.getXDHUEncoding(publicKey)));
        }
        return RubyString.newString(getRuntime(), sb);
    }

    private static StringBuilder bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xFF));
        return sb;
    }

    static boolean isXDHAlgorithm(final String alg) {
        return "X25519".equalsIgnoreCase(alg) || "X448".equalsIgnoreCase(alg) || "XDH".equalsIgnoreCase(alg);
    }

    static boolean isXDHKey(final PublicKey key) {
        return key != null && isXDHAlgorithm(key.getAlgorithm());
    }
}
