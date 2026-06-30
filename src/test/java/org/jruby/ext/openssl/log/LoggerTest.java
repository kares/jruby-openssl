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

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import org.jruby.ext.openssl.OpenSSL;
import org.jruby.ext.openssl.OpenSSLHelper;
import org.jruby.runtime.builtin.IRubyObject;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class LoggerTest extends OpenSSLHelper {

    private String originalLogProperty;
    private PrintStream originalOut;
    private ByteArrayOutputStream capturedOut;
    private java.util.logging.Logger capturedJulLogger;
    private TestLogHandler capturedJulHandler;

    @BeforeEach
    public void setUp() throws Exception {
        originalLogProperty = System.getProperty("jruby.openssl.log.logger");
        setUpRuntime();
    }

    @AfterEach
    public void tearDown() {
        try {
            restoreJulLogger();
            restoreLogProperty();
            restoreLoggerFactory();
            restoreStderr();
            restoreSystemOut();
        } finally {
            tearDownRuntime();
        }
    }

    // warn

    @Test
    public void warnUsesRubyStderrWhenRuntimeProvided() {
        replaceRubyStderr();

        final Logger logger = Logger.getLogger("test.warn");
        assertInstanceOf(DefaultLogger.class, logger);
        logger.warn(runtime, "logger-warn");

        assertEquals("[test.warn] logger-warn\n", capturedRubyStderr());
    }

    @Test
    public void warnWithCallerIncludesRubyCaller() {
        replaceRubyStderr();

        runtime.executeScript(
            "logger = org.jruby.ext.openssl.log::Logger.getLogger('test.trace')\n" +
            "def outer(logger)\n" +
            "  inner(logger)\n" +
            "end\n" +
            "def inner(logger)\n" +
            "  logger.warnWithCaller(JRuby.runtime, 'trace-warn')\n" +
            "end\n" +
            "outer(logger)", "TEST.rb"
        );

        final String stderr = capturedRubyStderr();
        assertEquals("[test.trace] trace-warn <TEST.rb:3:in `outer'>\n", stderr);
    }

    // debug (off by default)

    @Test
    public void debugIsSuppressedByDefault() {
        Assertions.assertFalse(OpenSSL.isDebug(), "debug should be off by default");

        captureSystemOut();
        final Logger logger = Logger.getLogger("test.debug.off");
        logger.debug(runtime, "should-not-appear");
        logger.debug(runtime, "also-hidden", new RuntimeException("ex"));

        assertEquals("", capturedSystemOut(), "debug output should be suppressed when debug is off");
    }

    @Test
    public void isDebugReturnsFalseByDefault() {
        final Logger logger = Logger.getLogger("test.debug.check");
        assertFalse(logger.isDebug(runtime));
        assertFalse(logger.isDebug(null));
    }

    @Test
    public void debugOutputsToStdoutWhenEnabled() {
        enableDebug();
        try {
            captureSystemOut();
            final Logger logger = Logger.getLogger("test.debug.on");
            assertInstanceOf(DefaultLogger.class, logger);
            logger.debug(runtime, "debug-msg");

            final String out = capturedSystemOut();
            assertEquals("[test.debug.on] debug-msg\n", out);
        } finally {
            disableDebug();
        }
    }

    @Test
    public void defaultLoggerUsesShortName() {
        enableDebug();
        try {
            captureSystemOut();
            final Logger logger = Logger.getLogger("org.jruby.ext.openssl.PKeyRSA");
            logger.debug(runtime, "short-name-test");

            assertEquals("[PKeyRSA] short-name-test\n", capturedSystemOut());
        } finally {
            disableDebug();
        }
    }

    @Test
    public void debugStackIncludesExceptionInfo() {
        final String out;
        enableDebug();
        try {
            captureSystemOut();
            final Logger logger = Logger.getLogger("test.debug.stack");
            logger.debugStack(runtime, "stack-msg", new RuntimeException("trace-me"));

            out = capturedSystemOut();
            String line0 = out.split(System.lineSeparator())[0];
            assertEquals("[test.debug.stack] stack-msg java.lang.RuntimeException: trace-me", line0);
        } finally {
            disableDebug();
            restoreSystemOut();
        }
    }

    @Test
    public void debugStackSuppressedWhenDebugOff() {
        assertFalse(OpenSSL.isDebug());

        captureSystemOut();
        final Logger logger = Logger.getLogger("test.debug.stack.off");
        logger.debugStack(runtime, "hidden-stack", new RuntimeException("nope"));

        assertEquals("", capturedSystemOut(), "debugStack should be suppressed when debug is off");
    }

    // info - currently maps to debug

    @Test
    public void infoSuppressedWhenDebugOff() {
        assertFalse(OpenSSL.isDebug());

        captureSystemOut();
        final Logger logger = Logger.getLogger("test.info.off");
        logger.info(runtime, "info-hidden");

        assertEquals("", capturedSystemOut(), "info suppressed when debug is off?");
    }

    // debug with null runtime (global/static fallback)

    @Test
    public void debugWithNullRuntimeOutputsToStdout() {
        enableDebug();
        try {
            captureSystemOut();
            final Logger logger = Logger.getLogger("test.debug.null");
            logger.debug(null, "null-runtime-msg");

            final String out = capturedSystemOut();
            assertEquals("[test.debug.null] null-runtime-msg\n", out);
        } finally {
            disableDebug();
        }
    }

    @Test
    public void julDebugLogsToFine() {
        enableDebug();
        try {
            System.setProperty("jruby.openssl.log.logger", "jul");
            LoggingSupport.boostrapLoggerFactory();

            final TestLogHandler handler = captureJulLogger("test.jul.debug", Level.FINE);
            final Logger logger = Logger.getLogger("test.jul.debug");
            assertInstanceOf(JULLogger.class, logger);

            logger.debug(runtime, "debug-msg");

            final LogRecord record = onlyRecord(handler);
            assertEquals(Level.FINE, record.getLevel());
            assertEquals("debug-msg", record.getMessage());
        } finally {
            disableDebug();
        }
    }

    @Test
    public void julWarnWithCallerIncludesRubyCaller() {
        System.setProperty("jruby.openssl.log.logger", "jul");
        LoggingSupport.boostrapLoggerFactory();

        final TestLogHandler handler = captureJulLogger("test.jul.trace", Level.WARNING);

        runtime.executeScript(
            "logger = org.jruby.ext.openssl.log::Logger.getLogger('test.jul.trace')\n" +
            "def outer(logger)\n" +
            "  inner(logger)\n" +
            "end\n" +
            "def inner(logger)\n" +
            "  logger.warnWithCaller(JRuby.runtime, 'trace-warn')\n" +
            "end\n" +
            "outer(logger)", "TEST.rb"
        );

        final LogRecord record = onlyRecord(handler);
        assertEquals(Level.WARNING, record.getLevel());
        assertEquals("trace-warn <TEST.rb:3:in `outer'>", record.getMessage());
    }

    private void enableDebug() {
        runtime.evalScriptlet("OpenSSL.debug = true");
    }

    private void disableDebug() {
        runtime.evalScriptlet("OpenSSL.debug = false");
    }

    private void captureSystemOut() {
        originalOut = System.out;
        capturedOut = new ByteArrayOutputStream();
        System.setOut(new PrintStream(capturedOut));
    }

    private String capturedSystemOut() {
        System.out.flush();
        return capturedOut.toString();
    }

    private void restoreSystemOut() {
        if (originalOut != null) {
            System.setOut(originalOut);
            originalOut = null;
        }
    }

    private void restoreLogProperty() {
        if (originalLogProperty == null) System.clearProperty("jruby.openssl.log.logger");
        else System.setProperty("jruby.openssl.log.logger", originalLogProperty);
    }

    private void restoreLoggerFactory() {
        LoggingSupport.loggerFactory = LoggingSupport.defaultLoggerFactory();
    }

    private TestLogHandler captureJulLogger(final String name, final Level level) {
        capturedJulLogger = java.util.logging.Logger.getLogger(name);
        capturedJulLogger.setUseParentHandlers(false);
        capturedJulLogger.setLevel(level);
        capturedJulHandler = new TestLogHandler();
        capturedJulHandler.setLevel(Level.ALL);
        capturedJulLogger.addHandler(capturedJulHandler);
        return capturedJulHandler;
    }

    private void restoreJulLogger() {
        if (capturedJulLogger == null || capturedJulHandler == null) return;

        capturedJulLogger.removeHandler(capturedJulHandler);
        capturedJulLogger.setUseParentHandlers(true);
        capturedJulLogger.setLevel(null);
        capturedJulLogger = null;
        capturedJulHandler = null;
    }

    private LogRecord onlyRecord(final TestLogHandler handler) {
        assertEquals(1, handler.records.size(), "expected exactly one JUL record");
        return handler.records.get(0);
    }

    private String capturedRubyStderr() {
        final IRubyObject result = runtime.evalScriptlet("$__captured_stderr__.string");
        return result.toString();
    }

    private void replaceRubyStderr() {
        runtime.evalScriptlet(
            "require 'stringio'\n" +
            "$__old_stderr__ = $stderr\n" +
            "$__captured_stderr__ = StringIO.new\n" +
            "$stderr = $__captured_stderr__"
        );
    }

    private void restoreStderr() {
        if (runtime == null) return;
        runtime.evalScriptlet(
            "if defined?($__old_stderr__) && $__old_stderr__\n" +
            "  $stderr = $__old_stderr__\n" +
            "end"
        );
    }

    private static final class TestLogHandler extends Handler {
        private final List<LogRecord> records = new ArrayList<>();

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
