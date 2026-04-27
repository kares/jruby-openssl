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

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.asn1.ASN1BMPString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralString;
import org.bouncycastle.asn1.ASN1GraphicString;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1NumericString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1T61String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.ASN1UniversalString;
import org.bouncycastle.asn1.ASN1VideotexString;
import org.bouncycastle.asn1.ASN1VisibleString;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;

public final class ASN1Shim {

    private ASN1Shim() {}

    // tag class constants — same values as BERTags but always available
    public static final int TAG_UNIVERSAL        = BERTags.UNIVERSAL;
    public static final int TAG_APPLICATION      = BERTags.APPLICATION;
    public static final int TAG_CONTEXT_SPECIFIC = BERTags.CONTEXT_SPECIFIC;
    public static final int TAG_PRIVATE          = BERTags.PRIVATE;

    /** extract the inner object from a tagged object */
    public static ASN1Primitive getTaggedObject(ASN1TaggedObject tagged) {
        return tagged.getBaseObject().toASN1Primitive();
    }

    /** decode parsed constructed tagged content as universal SEQUENCE */
    public static ASN1Sequence getBaseUniversalSequence(ASN1TaggedObject tagged) {
        try {
            return (ASN1Sequence) tagged.getBaseUniversal(false, BERTags.SEQUENCE);
        } catch (IllegalStateException | IllegalArgumentException e) {
            return null;
        }
    }

    /** regular BC represents application/private tags as ASN1TaggedObject */
    public static ApplicationSpecific getApplicationSpecific(ASN1Primitive obj) throws IOException {
        return null;
    }

    /** get tag class (UNIVERSAL / APPLICATION / CONTEXT_SPECIFIC / PRIVATE) */
    public static int getTagClass(ASN1TaggedObject tagged) {
        return tagged.getTagClass();
    }

    /** create a DERTaggedObject with explicit tag class */
    public static ASN1TaggedObject newDERTaggedObject(boolean explicit, int tagClass, int tagNo, ASN1Encodable obj) {
        return new DERTaggedObject(explicit, tagClass, tagNo, obj);
    }

    /**
     * Decode an ASN.1 string primitive.
     * @return {String typeName, byte[] rawBytes} or null if obj is not a recognized string type
     */
    public static Object[] decodeString(ASN1Primitive obj) {
        if (obj instanceof ASN1UTF8String) {
            byte[] stringBytes = ((ASN1UTF8String) obj).getString().getBytes(StandardCharsets.UTF_8);
            return new Object[] { "UTF8String", stringBytes };
        }
        if (obj instanceof ASN1UniversalString) {
            return new Object[] { "UniversalString", ((ASN1UniversalString) obj).getOctets() };
        }
        if (obj instanceof ASN1BMPString) {
            return decodeBMPString(((ASN1BMPString) obj).getString());
        }
        // remaining string types — use getString() via ASN1String interface
        if (obj instanceof ASN1String) {
            final String stringType = stringTypeName(obj);
            if (stringType != null) {
                byte[] stringBytes = ((ASN1String) obj).getString().getBytes(StandardCharsets.ISO_8859_1);
                return new Object[] { stringType, stringBytes };
            }
        }
        return null;
    }

    private static String stringTypeName(final ASN1Primitive obj) {
        if (obj instanceof ASN1NumericString) return "NumericString";
        if (obj instanceof ASN1PrintableString) return "PrintableString";
        if (obj instanceof ASN1IA5String) return "IA5String";
        if (obj instanceof ASN1T61String) return "T61String";
        if (obj instanceof ASN1GeneralString) return "GeneralString";
        if (obj instanceof ASN1VideotexString) return "VideotexString";
        if (obj instanceof ASN1VisibleString) return "ISO64String";
        if (obj instanceof ASN1GraphicString) return "GraphicString";
        return null;
    }

    private static Object[] decodeBMPString(final String val) {
        byte[] bytes = new byte[val.length() * 2];
        for (int i = 0; i < val.length(); i++) {
            char c = val.charAt(i);
            bytes[i * 2] = (byte) ((c >> 8) & 0xff);
            bytes[i * 2 + 1] = (byte) (c & 0xff);
        }
        return new Object[] { "BMPString", bytes };
    }
}
