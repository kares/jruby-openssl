/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Karol Bucek
 */
package org.jruby.ext.openssl.shim;

public abstract class ErrorShim {
    public static boolean isFipsOperationError(final Throwable ex) {
        return false;
    }
}
