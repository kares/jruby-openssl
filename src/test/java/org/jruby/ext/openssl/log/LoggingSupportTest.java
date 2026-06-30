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

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

public class LoggingSupportTest {

    private final String originalLogProperty = System.getProperty("jruby.openssl.log.logger");
    private final Function<String, Logger> originalLoggerFactory = LoggingSupport.loggerFactory;

    @AfterEach
    public void tearDown() {
        if (originalLogProperty == null) System.clearProperty("jruby.openssl.log.logger");
        else System.setProperty("jruby.openssl.log.logger", originalLogProperty);
        LoggingSupport.loggerFactory = originalLoggerFactory;
    }

    @Test
    public void bootstrapKeepsDefaultLoggerWhenPropertyUnset() {
        System.clearProperty("jruby.openssl.log.logger");

        LoggingSupport.boostrapLoggerFactory();

        assertInstanceOf(DefaultLogger.class, Logger.getLogger("test.example"));
    }

    @Test
    public void bootstrapUsesJulLoggerWhenRequested() {
        System.setProperty("jruby.openssl.log.logger", "jul");

        LoggingSupport.boostrapLoggerFactory();

        assertInstanceOf(JULLogger.class, Logger.getLogger("test.example"));
    }

    @Test
    public void julLoggerEmitsInfoRecord() {
        final String name = "test.jul.info";
        final java.util.logging.Logger jul = java.util.logging.Logger.getLogger(name);
        final Level originalLevel = jul.getLevel();
        final boolean originalUseParentHandlers = jul.getUseParentHandlers();
        final CapturingHandler handler = new CapturingHandler();

        try {
            jul.setUseParentHandlers(false);
            jul.setLevel(Level.ALL);
            handler.setLevel(Level.ALL);
            jul.addHandler(handler);

            new JULLogger(name).info(null, "info-msg");

            assertEquals(1, handler.records.size());
            assertEquals(Level.INFO, handler.records.get(0).getLevel());
            assertEquals("info-msg", handler.records.get(0).getMessage());
        }
        finally {
            jul.removeHandler(handler);
            jul.setLevel(originalLevel);
            jul.setUseParentHandlers(originalUseParentHandlers);
        }
    }

    private static final class CapturingHandler extends Handler {
        final List<LogRecord> records = new ArrayList<>();

        @Override
        public void publish(final LogRecord record) {
            records.add(record);
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    }

}
