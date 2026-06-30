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
package org.jruby.ext.openssl.log;

import java.util.logging.Level;

import org.jruby.Ruby;
import org.jruby.ext.openssl.OpenSSL;
import org.jruby.ext.openssl.util.RubySupport;
import org.jruby.runtime.ThreadContext;

final class JULLogger implements Logger {

    private final java.util.logging.Logger logger;

    JULLogger(final String name) {
        this.logger = java.util.logging.Logger.getLogger(name);
    }

    @Override
    public boolean isDebug(final Ruby runtime) {
        return OpenSSL.isDebug() && logger.isLoggable(Level.FINE);
    }

    private boolean isInfo() {
        return logger.isLoggable(Level.INFO);
    }

    private boolean isWarn() {
        return OpenSSL.isWarn() && logger.isLoggable(Level.WARNING);
    }

    @Override
    public void debug(final Ruby runtime, final CharSequence msg) {
        if (!isDebug(runtime)) return;

        logger.log(Level.FINE, msgWithPrefix(msg, false));
    }

    @Override
    public void debug(final Ruby runtime, final CharSequence msg, final Throwable ex) {
        if (!isDebug(runtime)) return;

        logger.log(Level.FINE, msgWithPrefix(msg, true) + ex);
    }

    @Override
    public void debugStack(final Ruby runtime, final CharSequence msg, final Throwable ex) {
        if (!isDebug(runtime)) return;

        logger.log(Level.FINE, msgWithPrefix(msg, false), ex);
    }

    @Override
    public void info(final Ruby runtime, final CharSequence msg) {
        if (!isInfo()) return;

        logger.log(Level.INFO, msgWithPrefix(msg, false));
    }

    @Override
    public void warn(final Ruby runtime, final CharSequence msg) {
        if (!isWarn()) return;

        logger.log(Level.WARNING, msgWithPrefix(msg, false));
    }

    @Override
    public void warn(final Ruby runtime, final CharSequence msg, final Throwable ex) {
        if (!isWarn()) return;

        logger.log(Level.WARNING, msgWithPrefix(msg, true) + ex);
    }

    @Override
    public void warnWithCaller(final Ruby runtime, CharSequence msg) {
        if (!isWarn()) return;

        if (runtime != null) {
            final ThreadContext context = runtime.getCurrentContext();
            final CharSequence caller = RubySupport.callerTraceAt(context, 1);
            if (caller != null) msg = msgWithPrefix(msg, true) + '<' + caller + '>';
            else msg = msgWithPrefix(msg, false);
        }
        else {
            msg = msgWithPrefix(msg, false);
        }

        logger.log(Level.WARNING, msg.toString());
    }

    private static String msgWithPrefix(final CharSequence msg, final boolean space) {
        return (msg == null ? "" : msg) + (space ? " " : "");
    }
}