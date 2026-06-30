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

import org.jruby.Ruby;
import org.jruby.ext.openssl.OpenSSL;
import org.jruby.ext.openssl.util.RubySupport;
import org.jruby.runtime.ThreadContext;

final class DefaultLogger implements Logger {

    private final String name;

    DefaultLogger(final String name) {
        this.name = name.replace("org.jruby.ext.openssl.", "");
    }

    @Override
    public boolean isDebug(final Ruby runtime) {
        return OpenSSL.isDebug();
    }

    private boolean isWarn() {
        return OpenSSL.isWarn();
    }

    @Override
    public void debug(final Ruby runtime, final CharSequence msg) {
        if (!isDebug(runtime)) return;

        System.out.println(msgWithPrefix(msg, false));
    }

    @Override
    public void debug(final Ruby runtime, final CharSequence msg, final Throwable ex) {
        if (!isDebug(runtime)) return;

        System.out.println(msgWithPrefix(msg, true) + ex);
    }

    @Override
    public void debugStack(final Ruby runtime, final CharSequence msg, final Throwable ex) {
        if (!isDebug(runtime)) return;

        synchronized (System.out) {
            System.out.print(msgWithPrefix(msg, true));
            ex.printStackTrace(System.out);
        }
    }

    @Override
    public void info(Ruby runtime, CharSequence msg) {
        debug(runtime, msg);
    }

    @Override
    public void warn(final Ruby runtime, final CharSequence msg) {
        if (!isWarn()) return;

        final String message = msgWithPrefix(msg, false);
        if (runtime != null) {
            OpenSSL.doWarn(runtime.getCurrentContext(), message);
        }
        else {
            System.err.println(message);
        }
    }

    @Override
    public void warn(final Ruby runtime, final CharSequence msg, final Throwable ex) {
        if (!isWarn()) return;

        final String message = msgWithPrefix(msg, true) + ex;
        if (runtime != null) {
            OpenSSL.doWarn(runtime.getCurrentContext(), message);
        }
        else {
            System.err.println(message);
        }
    }


    @Override
    public void warnWithCaller(final Ruby runtime, CharSequence msg) {
        if (!isWarn()) return;

        if (runtime != null) {
            final ThreadContext context = runtime.getCurrentContext();
            final CharSequence caller = RubySupport.callerTraceAt(context, 1);
            if (caller != null) msg = msgWithPrefix(msg, true) + '<' + caller + '>';
            else msg = msgWithPrefix(msg, false);
            OpenSSL.doWarn(context, msg);
        }
        else {
            System.err.println(msgWithPrefix(msg, false));
        }
    }

    private String msgWithPrefix(final CharSequence msg, final boolean space) {
        return '[' + name + "] " + (msg == null ? "" : msg) + (space ? ' ' : "");
    }
}
