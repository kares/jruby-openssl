/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Karol Bucek
 */
package org.jruby.ext.openssl.shim;

import org.jruby.ext.openssl.Cipher;

public abstract class CipherShim {

    public static boolean isCipherAllowed(final Cipher.Algorithm algorithm) {
        assert algorithm != null;
        return true;
    }
}
