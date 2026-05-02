/*
 * The MIT License
 *
 * Copyright 2026 Karol Bucek.
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
package org.jruby.ext.openssl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagFactory;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyClass;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.util.PEMGenerator;
import org.jruby.runtime.Arity;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

import static org.jruby.ext.openssl.util.RubySupport.newError;

@JRubyClass(name = "OpenSSL::PKCS12")
public class PKCS12 extends RubyObject {
    private static final long serialVersionUID = 8087765252844713771L;

    private static final ObjectAllocator ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new PKCS12(runtime, klass);
        }
    };

    private static final int KEY_EX = 0x10;
    private static final int KEY_SIG = 0x80;

    static void createPKCS12(final Ruby runtime, final RubyModule OpenSSL, final RubyClass OpenSSLError) {
        final RubyClass _PKCS12 = OpenSSL.defineClassUnder("PKCS12", runtime.getObject(), ALLOCATOR);
        _PKCS12.defineClassUnder("PKCS12Error", OpenSSLError, OpenSSLError.getAllocator());
        _PKCS12.defineAnnotatedMethods(PKCS12.class);

        // from OpenSSL's MSIE-specific key usage constants
        _PKCS12.setConstant("KEY_EX", runtime.newFixnum(KEY_EX));
        _PKCS12.setConstant("KEY_SIG", runtime.newFixnum(KEY_SIG));
    }

    private IRubyObject key;
    private IRubyObject certificate;
    private IRubyObject caCerts;
    private byte[] storeBytes; // DER

    public PKCS12(Ruby runtime, RubyClass type) {
        super(runtime, type);
        this.key = runtime.getNil();
        this.certificate = runtime.getNil();
        this.caCerts = runtime.getNil();
    }

    @JRubyMethod(meta = true, rest = true)
    public static IRubyObject create(final ThreadContext context,
                                     final IRubyObject self,
                                     final IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        Arity.checkArgumentCount(runtime, args, 4, 10);

        final PKCS12 pkcs12 = new PKCS12(runtime, (RubyClass) self);
        pkcs12.generate(context, args);
        return pkcs12;
    }

    @JRubyMethod(name = "initialize", optional = 2, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context,
                                  final IRubyObject[] args,
                                  final Block unusedBlock) {
        final Ruby runtime = context.runtime;
        if (Arity.checkArgumentCount(runtime, args, 0, 2) == 0) {
            storeBytes = null;
            return this;
        }

        final RubyString input = StringHelper.readPossibleDERInput(context, args[0]);
        storeBytes = input.getBytes();

        final IRubyObject passArg = args.length > 1 ? args[1] : runtime.getNil();
        final char[] password = toPasswordChars(passArg);
        try {
            final KeyStore store = SecurityHelper.getKeyStore("PKCS12");
            store.load(new ByteArrayInputStream(storeBytes), password);
            loadEntries(context, store, password);
        }
        catch (Exception e) {
            if (e instanceof RaiseException) throw (RaiseException) e;
            throw newPKCS12Error(runtime, e);
        }
        finally {
            clearChars(password);
        }

        return this;
    }

    @JRubyMethod(name = "initialize_copy", visibility = Visibility.PRIVATE)
    public IRubyObject initialize_copy(final IRubyObject original) {
        if (this == original) return this;
        checkFrozen();

        final PKCS12 that = (PKCS12) original;
        this.key = that.key;
        this.certificate = that.certificate;
        this.caCerts = that.caCerts;
        this.storeBytes = that.storeBytes == null ? null : that.storeBytes.clone();
        return this;
    }

    @JRubyMethod
    public IRubyObject key() {
        return key;
    }

    @JRubyMethod
    public IRubyObject certificate() {
        return certificate;
    }

    @JRubyMethod(name = "ca_certs")
    public IRubyObject ca_certs() {
        return caCerts;
    }

    @JRubyMethod(name = "to_der")
    public IRubyObject to_der(final ThreadContext context) {
        if (storeBytes == null) return context.runtime.getNil();
        return StringHelper.newString(context.runtime, storeBytes.clone());
    }

    private void generate(final ThreadContext context, final IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        final IRubyObject passArg = args[0];
        final IRubyObject nameArg = args[1];
        final IRubyObject keyArg = args[2];
        final IRubyObject certArg = args[3];
        final IRubyObject caArg = args.length > 4 ? args[4] : runtime.getNil();

        if (!(keyArg instanceof PKey)) throw runtime.newTypeError(keyArg, PKey._PKey(runtime).getClass("PKey"));
        if (!(certArg instanceof X509Cert)) throw runtime.newTypeError(certArg, X509Cert._Certificate(runtime));

        validateCreateOptions(runtime, args);

        final char[] password = toPasswordChars(passArg);
        try {
            final PrivateKey privateKey = ((PKey) keyArg).getPrivateKey();
            if (privateKey == null) throw newPKCS12Error(runtime, "private key not set");

            final Certificate[] chain = certificateChain(runtime, (X509Cert) certArg, caArg);
            final KeyStore store = SecurityHelper.getKeyStore("PKCS12");
            store.load(null, null);
            store.setKeyEntry(aliasName(nameArg), privateKey, null, chain);

            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            store.store(out, password);
            storeBytes = out.toByteArray();

            key = keyArg;
            certificate = certArg;
            caCerts = caArg.isNil() ? runtime.getNil() : caArg;
        }
        catch (Exception e) {
            if (e instanceof RaiseException) throw (RaiseException) e;
            throw newPKCS12Error(runtime, e);
        }
        finally {
            clearChars(password);
        }
    }

    private void loadEntries(final ThreadContext context, final KeyStore store, final char[] password) throws Exception {
        final Ruby runtime = context.runtime;
        final Enumeration<String> aliases = store.aliases();

        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            if (!store.isKeyEntry(alias)) continue;

            final Certificate javaCertificate = store.getCertificate(alias);
            if (javaCertificate != null) {
                certificate = X509Cert.wrap(context, javaCertificate);
            }

            final Key javaKey = store.getKey(alias, password);
            if (javaKey != null) {
                key = readPKey(context, javaKey.getEncoded());
            }

            final RubyArray chain = runtime.newArray();
            final Certificate[] javaChain = store.getCertificateChain(alias);
            if (javaChain != null) {
                for (Certificate chainCert : javaChain) {
                    if (javaCertificate != null && sameCertificate(javaCertificate, chainCert)) continue;
                    chain.add(X509Cert.wrap(context, chainCert));
                }
            }
            caCerts = chain;
            return;
        }

        RubyArray certs = runtime.newArray();
        final Enumeration<String> certAliases = store.aliases();
        while (certAliases.hasMoreElements()) {
            final String alias = certAliases.nextElement();
            if (!store.isCertificateEntry(alias)) continue;

            final Certificate cert = store.getCertificate(alias);
            if (cert != null) certs.add(X509Cert.wrap(context, cert));
        }

        if (certs.isEmpty() && storeBytes != null) {
            certs = readCertificateBags(context, password);
        }
        caCerts = certs;
    }

    private RubyArray readCertificateBags(final ThreadContext context, final char[] password) throws Exception {
        final Ruby runtime = context.runtime;
        final RubyArray certs = runtime.newArray();
        final PKCS12PfxPdu pfx = new PKCS12PfxPdu(storeBytes);
        final InputDecryptorProvider decryptor = new JcePKCSPBEInputDecryptorProviderBuilder()
            .setProvider(SecurityHelper.getSecurityProvider()).build(password);

        final ContentInfo[] infos = pfx.getContentInfos();
        for (ContentInfo info : infos) {
            final PKCS12SafeBagFactory factory;
            if (PKCSObjectIdentifiers.encryptedData.equals(info.getContentType())) {
                factory = new PKCS12SafeBagFactory(info, decryptor);
            }
            else {
                factory = new PKCS12SafeBagFactory(info);
            }

            final PKCS12SafeBag[] bags = factory.getSafeBags();
            for (PKCS12SafeBag bag : bags) {
                if (!PKCSObjectIdentifiers.certBag.equals(bag.getType())) continue;

                final X509CertificateHolder holder = (X509CertificateHolder) bag.getBagValue();
                certs.add(X509Cert.wrap(context, holder.getEncoded()));
            }
        }

        return certs;
    }

    private static IRubyObject readPKey(final ThreadContext context, final byte[] encoded) {
        final Ruby runtime = context.runtime;
        return PKey.PKeyModule.read(context, PKey._PKey(runtime), StringHelper.newString(runtime, encoded));
    }

    static Certificate[] certificateChain(final Ruby runtime, final X509Cert cert, final IRubyObject caArg) {

        final List<Certificate> certificates = new ArrayList<>();
        certificates.add(cert.getAuxCert());

        if (!caArg.isNil()) {
            final RubyArray ca = caArg.convertToArray();
            for (int i = 0; i < ca.size(); i++) {
                final IRubyObject item = ca.eltInternal(i);
                if (!(item instanceof X509Cert)) {
                    throw runtime.newTypeError(item, X509Cert._Certificate(runtime));
                }
                certificates.add(((X509Cert) item).getAuxCert());
            }
        }

        return certificates.toArray(new Certificate[certificates.size()]);
    }

    private static String aliasName(final IRubyObject name) {
        return name.isNil() ? "" : name.convertToString().asJavaString();
    }

    private static boolean sameCertificate(final Certificate cert1, final Certificate cert2)
        throws CertificateEncodingException { // Certificate#equals swallows exception
        final byte[] encoded1 = cert1.getEncoded();
        final byte[] encoded2 = cert2.getEncoded();
        if (encoded1.length != encoded2.length) return false;
        for (int i = 0; i < encoded1.length; i++) {
            if (encoded1[i] != encoded2[i]) return false;
        }
        return true;
    }

    private static void validateCreateOptions(final Ruby runtime, final IRubyObject[] args) {
        if (args.length > 5 && !args[5].isNil()) validatePBE(runtime, args[5]);
        if (args.length > 6 && !args[6].isNil()) validatePBE(runtime, args[6]);
        if (args.length > 7 && !args[7].isNil()) RubyNumeric.num2int(args[7]);
        if (args.length > 8 && !args[8].isNil()) RubyNumeric.num2int(args[8]);
        if (args.length > 9 && !args[9].isNil()) {
            final int keyType = RubyNumeric.num2int(args[9]);
            if (keyType != 0 && keyType != KEY_EX && keyType != KEY_SIG) {
                throw runtime.newArgumentError("Unknown key usage type " + keyType);
            }
        }
    }

    private static void validatePBE(final Ruby runtime, final IRubyObject pbe) {
        final String name = pbe.convertToString().asJavaString();
        if ("PBE-SHA1-3DES".equals(name) || "PBE-SHA1-RC2-40".equals(name)) return;
        throw runtime.newArgumentError("Unknown PBE algorithm " + pbe.inspect());
    }

    static char[] toPasswordChars(final IRubyObject passwd) {
        if (passwd == null || passwd.isNil()) return new char[0];

        final RubyString str = passwd.convertToString();
        final ByteList byteList = str.getByteList();

        return toPasswordChars(
                byteList.getUnsafeBytes(), byteList.getBegin(), byteList.getRealSize(),
                byteList.getEncoding().getCharset()
        );
    }

    // Package-private for testing
    static char[] toPasswordChars(final byte[] bytes, final int offset, final int length, Charset charset) {
        if (length == 0) return new char[0];

        if (charset == null) charset = StandardCharsets.ISO_8859_1;

        final ByteBuffer byteBuf = ByteBuffer.wrap(bytes, offset, length);
        final CharBuffer charBuf = charset.decode(byteBuf);

        final char[] result = new char[charBuf.remaining()];
        charBuf.get(result);

        // Clear the decoder's intermediate buffer
        if (charBuf.hasArray()) {
            Arrays.fill(charBuf.array(), '\0');
        }

        return result;
    }

    static void clearChars(final char[] chars) {
        if (chars.length > 0) Arrays.fill(chars, '\0');
    }

    private static RaiseException newPKCS12Error(final Ruby runtime, final Throwable e) {
        return newError(runtime, _PKCS12(runtime).getClass("PKCS12Error"), e);
    }

    private static RaiseException newPKCS12Error(final Ruby runtime, final String message) {
        return newError(runtime, _PKCS12(runtime).getClass("PKCS12Error"), message);
    }

    private static RubyClass _PKCS12(final Ruby runtime) {
        return runtime.getModule("OpenSSL").getClass("PKCS12");
    }
}
