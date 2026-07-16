
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

/*
 * Inlines every static method of org.jruby.ext.openssl.shim and the classes.
 * Classes that do not call into the shim are not rewritten at all.
 *
 * Run via the single-file source launcher (JDK 11+), see <i>Mavenfile</i>:
 *   java -classpath <compile classpath> src/build/java/ShimInliner.java <classes dir>
 *
 * NOTE: unlike ProGuard only removes the *call*; does not fold the constant left behind,
 * so a dead FIPS branch (and whatever it references) stays in the bytecode.
 */
public class ShimInliner {

    private static final String SHIM_PKG = "org/jruby/ext/openssl/shim/";

    public static void main(String[] args) throws Exception {
        final Path classesDir = Paths.get(args[0]);

        final List<Path> classFiles = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(classesDir)) {
            walk.filter(p -> p.toString().endsWith(".class")).forEach(classFiles::add);
        }

        // every static shim method is a candidate; instance members (ApplicationSpecific)
        // are left alone
        final Map<String, ClassNode> shims = new LinkedHashMap<>();
        for (Path p : classFiles) {
            ClassNode cn = read(p);
            if (cn.name.startsWith(SHIM_PKG)) shims.put(cn.name, cn);
        }
        if (shims.isEmpty()) {
            // already inlined (re-run over the same output dir) - unless a caller still points
            // at a shim we just cannot see, which would only blow up at class load
            if (referencedBy(classFiles, classesDir, SHIM_PKG)) {
                throw new IllegalStateException("shim classes are gone but still referenced - "
                        + classesDir + " is half-compiled, run a clean build");
            }
            System.out.println("[ShimInliner] no shim classes, nothing to do");
            return;
        }

        final Map<String, MethodNode> candidates = new HashMap<>();
        for (ClassNode cn : shims.values()) {
            for (MethodNode mn : cn.methods) {
                if ((mn.access & Opcodes.ACC_STATIC) != 0 && !"<clinit>".equals(mn.name)) {
                    candidates.put(cn.name + '.' + mn.name + mn.desc, mn);
                }
            }
        }

        // shim methods call each other (decodeString -> private helpers), so flatten the
        // shim bodies first - otherwise an inlined body keeps pointing at a shim class
        for (int pass = 0; pass < 3; pass++) {
            for (ClassNode cn : shims.values()) {
                for (MethodNode mn : cn.methods) inlineInto(cn, mn, candidates);
            }
        }

        int rewritten = 0, inlined = 0;
        for (Path p : classFiles) {
            ClassNode cn = read(p);
            if (cn.name.startsWith(SHIM_PKG)) continue;
            int n = 0;
            for (MethodNode mn : cn.methods) n += inlineInto(cn, mn, candidates);
            if (n > 0) {
                Files.write(p, write(cn));
                rewritten++;
                inlined += n;
                System.out.println("[ShimInliner] " + cn.name + ": inlined " + n + " call(s)");
            }
        }

        int deleted = 0;
        for (String shim : shims.keySet()) {
            if (referencedBy(classFiles, classesDir, shim)) {
                System.out.println("[ShimInliner] keeping " + shim + " - still referenced");
                continue;
            }
            Files.delete(classesDir.resolve(shim + ".class"));
            deleted++;
        }
        System.out.println("[ShimInliner] inlined " + inlined + " call(s) in " + rewritten
                + " class(es), deleted " + deleted + " of " + shims.size() + " shim class(es)");
    }

    /** @return number of call sites inlined */
    private static int inlineInto(ClassNode owner, MethodNode method, Map<String, MethodNode> candidates)
            throws Exception {
        if (method.instructions == null || method.instructions.size() == 0) return 0;

        final List<MethodInsnNode> calls = new ArrayList<>();
        for (AbstractInsnNode insn : method.instructions.toArray()) {
            if (insn.getOpcode() == Opcodes.INVOKESTATIC) {
                MethodInsnNode call = (MethodInsnNode) insn;
                if (call.owner.startsWith(SHIM_PKG) && candidates.containsKey(key(call))) calls.add(call);
            }
        }
        if (calls.isEmpty()) return 0;

        // A body that catches exceptions may only be inlined where the operand stack is
        // otherwise empty: entering a handler discards the stack, so anything the caller
        // had parked there would be lost. Indices must be taken before any splicing.
        Frame<BasicValue>[] frames = null;
        final Map<MethodInsnNode, Integer> indices = new HashMap<>();
        for (MethodInsnNode call : calls) {
            if (!candidates.get(key(call)).tryCatchBlocks.isEmpty()) {
                if (frames == null) frames = new Analyzer<>(new BasicInterpreter()).analyze(owner.name, method);
                indices.put(call, method.instructions.indexOf(call));
            }
        }

        int count = 0;
        for (MethodInsnNode call : calls) {
            MethodNode callee = candidates.get(key(call));
            if (!callee.tryCatchBlocks.isEmpty()) {
                Frame<BasicValue> frame = frames[indices.get(call)];
                int args = Type.getArgumentTypes(call.desc).length;
                if (frame == null || frame.getStackSize() - args != 0) {
                    System.out.println("[ShimInliner] skipping " + key(call) + " in " + owner.name
                            + '.' + method.name + " - catches exceptions, stack not empty");
                    continue;
                }
            }
            splice(method, call, callee);
            count++;
        }
        return count;
    }

    private static void splice(MethodNode method, MethodInsnNode call, MethodNode callee) {
        final int base = method.maxLocals; // callee locals live above the caller's
        final Type[] argTypes = Type.getArgumentTypes(call.desc);

        final InsnList body = new InsnList();
        int[] slots = new int[argTypes.length];
        for (int i = 0, slot = 0; i < argTypes.length; i++) {
            slots[i] = slot;
            slot += argTypes[i].getSize();
        }
        for (int i = argTypes.length - 1; i >= 0; i--) { // arguments come off the stack in reverse
            body.add(new VarInsnNode(argTypes[i].getOpcode(Opcodes.ISTORE), base + slots[i]));
        }

        final Map<LabelNode, LabelNode> labels = new HashMap<>();
        for (AbstractInsnNode insn : callee.instructions.toArray()) {
            if (insn instanceof LabelNode) labels.put((LabelNode) insn, new LabelNode());
        }
        final LabelNode end = new LabelNode();

        for (AbstractInsnNode insn : callee.instructions.toArray()) {
            // the callee's line numbers belong to another source file, and frames get
            // recomputed on write
            if (insn instanceof LineNumberNode || insn instanceof FrameNode) continue;

            int op = insn.getOpcode();
            if (op >= Opcodes.IRETURN && op <= Opcodes.RETURN) {
                body.add(new JumpInsnNode(Opcodes.GOTO, end)); // return value stays on the stack
                continue;
            }
            AbstractInsnNode copy = insn.clone(labels);
            if (copy instanceof VarInsnNode) ((VarInsnNode) copy).var += base;
            else if (copy instanceof IincInsnNode) ((IincInsnNode) copy).var += base;
            body.add(copy);
        }
        body.add(end);

        for (TryCatchBlockNode tcb : callee.tryCatchBlocks) {
            method.tryCatchBlocks.add(new TryCatchBlockNode(
                    labels.get(tcb.start), labels.get(tcb.end), labels.get(tcb.handler), tcb.type));
        }

        method.instructions.insertBefore(call, body);
        method.instructions.remove(call);
        method.maxLocals = base + callee.maxLocals;
    }

    private static boolean referencedBy(List<Path> classFiles, Path classesDir, String shim) throws IOException {
        final byte[] needle = shim.getBytes("UTF-8"); // the constant pool stores it verbatim
        for (Path p : classFiles) {
            if (p.startsWith(classesDir.resolve(SHIM_PKG))) continue;
            if (indexOf(Files.readAllBytes(p), needle) >= 0) return true;
        }
        return false;
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    private static String key(MethodInsnNode call) {
        return call.owner + '.' + call.name + call.desc;
    }

    private static ClassNode read(Path p) throws IOException {
        ClassNode cn = new ClassNode();
        new ClassReader(Files.readAllBytes(p)).accept(cn, ClassReader.SKIP_FRAMES);
        return cn;
    }

    private static byte[] write(ClassNode cn) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS) {
            @Override
            protected String getCommonSuperClass(String type1, String type2) {
                // resolved off the compile classpath we were launched with
                try {
                    return super.getCommonSuperClass(type1, type2);
                } catch (RuntimeException e) {
                    throw new IllegalStateException("cannot resolve " + type1 + " / " + type2, e);
                }
            }
        };
        cn.accept(cw);
        return cw.toByteArray();
    }
}
