/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Karol Bucek
 */
package org.jruby.ext.openssl.shim;

public abstract class ProviderShim {

    /**
     * Whether the provider is enforcing approved-only operation
     */
    public static boolean isInApprovedOnlyMode() {
        return false;
    }
}
