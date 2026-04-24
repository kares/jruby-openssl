package org.jruby.ext.openssl;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.ext.openssl.log.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class LoggerTest extends OpenSSLHelper {

    private PrintStream originalOut;
    private ByteArrayOutputStream capturedOut;

    @BeforeEach
    public void setUp() throws Exception {
        setUpRuntime();
    }

    @AfterEach
    public void tearDown() {
        try {
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
        assertFalse(OpenSSL.isDebug(), "debug should be off by default");

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
            logger.debug(runtime, "debug-msg");

            final String out = capturedSystemOut();
            assertEquals("[test.debug.on] debug-msg\n", out);
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
}
