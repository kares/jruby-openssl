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

public interface Logger {

    static Logger getLogger(final Class<?> type) {
        return getLogger(type.getName());
    }

    static Logger getLogger(final String name) {
        return LoggingSupport.loggerFactory.apply(name);
    }

    boolean isDebug(Ruby runtime);

    default void debug(CharSequence msg) {
        debug(null, msg);
    }

    void debug(Ruby runtime, CharSequence msg);

    default void debug(CharSequence msg, Throwable ex) {
        debug(null, msg, ex);
    }

    void debug(Ruby runtime, CharSequence msg, Throwable t);

    default void debugStack(Throwable ex) {
        debugStack(null, null, ex);
    }

    default void debugStack(CharSequence msg, Throwable ex) {
        debugStack(null, msg, ex);
    }

    void debugStack(Ruby runtime, CharSequence msg, Throwable ex);

    default void info(CharSequence msg) {
        info(null, msg);
    }

    void info(Ruby runtime, CharSequence msg);

    default void warn(CharSequence msg) {
        warn(null, msg);
    }

    void warn(Ruby runtime, CharSequence msg);

    void warn(Ruby runtime, CharSequence msg, Throwable t);

    default void warnWithCaller(Ruby runtime, CharSequence msg) {
        warn(runtime, msg);
    }
}
