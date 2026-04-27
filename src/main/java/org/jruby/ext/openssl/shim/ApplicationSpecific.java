package org.jruby.ext.openssl.shim;

import org.bouncycastle.asn1.ASN1Sequence;

/**
 * decoded older-BC application/private-specific representation
 */
public final class ApplicationSpecific {
    public final int tagClass;
    public final int tag;
    public final ASN1Sequence sequence;
    public final byte[] contents;

    ApplicationSpecific(int tagClass, int tag, ASN1Sequence sequence, byte[] contents) {
        this.tagClass = tagClass;
        this.tag = tag;
        this.sequence = sequence;
        this.contents = contents;
    }

    public boolean isConstructed() {
        return sequence != null;
    }
}
