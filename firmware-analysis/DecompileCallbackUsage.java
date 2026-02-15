// Ghidra headless script to find where recording callbacks stored by sub_FF8C3BFC are used
// State struct base loaded from DAT_ff8c2e24 = 0x70D8
// Offsets of interest:
//   +0x114 (= 0x71EC) — recording callback 1 (normally 0xFF85D370)
//   +0x118 (= 0x71F0) — recording callback 2 (normally 0xFF85D28C)
//   +0x6C  (= 0x7144) — recording buffer (normally 0x1AB94)
//
// Run with: analyzeHeadless <project_dir> <project_name> -process PRIMARY.BIN -noanalysis
//           -scriptPath <dir> -postScript DecompileCallbackUsage.java
//
//@category CHDK
//@author webcam-re

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import java.io.FileWriter;
import java.io.File;
import java.util.*;

public class DecompileCallbackUsage extends GhidraScript {

    // MJPEG state struct base address (value of DAT_ff8c2e24)
    private static final long STATE_BASE = 0x70D8L;

    // Offsets we're searching for (relative to state base)
    private static final int[] OFFSETS = { 0x114, 0x118, 0x6C };
    private static final String[] OFFSET_NAMES = {
        "+0x114 (recording callback 1, normally 0xFF85D370)",
        "+0x118 (recording callback 2, normally 0xFF85D28C)",
        "+0x6C  (recording buffer, normally 0x1AB94)"
    };

    // RAM addresses = STATE_BASE + offset
    // 0x71EC, 0x71F0, 0x7144

    // Key functions to decompile
    private static final long[] DECOMPILE_TARGETS = {
        0xFF8C1FE4L, // FUN_ff8c1fe4_PipelineFrameCallback
        0xFF8C21C8L, // FUN_ff8c21c8 — large pipeline handler (switch on +0x5C)
        0xFF8C2938L, // FUN_ff8c2938 — frame builder
        0xFF85D370L, // Recording callback 1 itself
        0xFF85D28CL, // Recording callback 2 itself
        0xFF8C3BFCL, // sub_FF8C3BFC — RecordingPipelineSetup (stores the callbacks)
        0xFF85D98CL, // sub_FF85D98C — movie_rec.c patched function (calls sub_FF8C3BFC)
        0xFF85E03CL, // movie_record_task entry point
    };

    private static final String[] DECOMPILE_NAMES = {
        "FUN_ff8c1fe4_PipelineFrameCallback",
        "FUN_ff8c21c8_PipelineHandler",
        "FUN_ff8c2938_FrameBuilder",
        "FUN_ff85d370_RecordingCallback1",
        "FUN_ff85d28c_RecordingCallback2",
        "sub_FF8C3BFC_RecordingPipelineSetup",
        "sub_FF85D98C_MovieRecPatched",
        "FUN_ff85e03c_MovieRecordTask",
    };

    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        StringBuilder output = new StringBuilder();
        output.append("========================================================================\n");
        output.append("Recording Callback Usage Analysis\n");
        output.append("Firmware: IXUS 870 IS / SD 880 IS, version 1.01a\n");
        output.append("MJPEG state struct base: 0x" + Long.toHexString(STATE_BASE) + "\n");
        output.append("========================================================================\n\n");

        // ============================================================
        // PART 1: Search for references to the RAM addresses
        // ============================================================
        output.append("########################################################################\n");
        output.append("# PART 1: Cross-Reference Scan for State Struct Offsets\n");
        output.append("#\n");
        output.append("# Looking for code that reads/writes these RAM addresses:\n");
        for (int i = 0; i < OFFSETS.length; i++) {
            long addr = STATE_BASE + OFFSETS[i];
            output.append("#   0x" + Long.toHexString(addr) + " = state[" + OFFSET_NAMES[i] + "]\n");
        }
        output.append("########################################################################\n\n");

        ReferenceManager refMgr = currentProgram.getReferenceManager();
        Memory memory = currentProgram.getMemory();
        FunctionManager funcMgr = currentProgram.getFunctionManager();

        // For each offset, search for references to the RAM address
        Set<Long> functionsToDecompile = new LinkedHashSet<>();
        for (int i = 0; i < OFFSETS.length; i++) {
            long ramAddr = STATE_BASE + OFFSETS[i];
            Address targetAddr = toAddr(ramAddr);
            output.append("// --- References to state[" + OFFSET_NAMES[i] + "] at 0x" + Long.toHexString(ramAddr) + " ---\n");

            // Method 1: Direct references from Ghidra's reference database
            ReferenceIterator refs = refMgr.getReferencesTo(targetAddr);
            int refCount = 0;
            while (refs.hasNext()) {
                Reference ref = refs.next();
                Address fromAddr = ref.getFromAddress();
                Function func = funcMgr.getFunctionContaining(fromAddr);
                String funcName = (func != null) ? func.getName() + " @ " + func.getEntryPoint() : "(no function)";
                String refType = ref.getReferenceType().getName();
                output.append("//   Ref from " + fromAddr + " in " + funcName + " [" + refType + "]\n");
                if (func != null) {
                    functionsToDecompile.add(func.getEntryPoint().getOffset());
                }
                refCount++;
            }
            if (refCount == 0) {
                output.append("//   (no direct references found in Ghidra database)\n");
            }

            // Method 2: Scan ROM literal pools for the address value
            output.append("//\n// --- ROM literal pool scan for 0x" + String.format("%08x", ramAddr) + " ---\n");
            int literalCount = 0;
            // Scan the ROM region for this 32-bit value
            Address searchStart = toAddr(0xFF810000L);
            Address searchEnd = toAddr(0xFFFFFFFFL);
            byte[] searchBytes = new byte[4];
            searchBytes[0] = (byte)(ramAddr & 0xFF);
            searchBytes[1] = (byte)((ramAddr >> 8) & 0xFF);
            searchBytes[2] = (byte)((ramAddr >> 16) & 0xFF);
            searchBytes[3] = (byte)((ramAddr >> 24) & 0xFF);

            Address found = memory.findBytes(searchStart, searchEnd, searchBytes, null, true, monitor);
            while (found != null && found.getOffset() < 0xFFFFFFFFL) {
                // Check if this literal pool entry is referenced by code
                ReferenceIterator litRefs = refMgr.getReferencesTo(found);
                boolean hasCodeRef = false;
                while (litRefs.hasNext()) {
                    Reference litRef = litRefs.next();
                    Address litFromAddr = litRef.getFromAddress();
                    Function litFunc = funcMgr.getFunctionContaining(litFromAddr);
                    String litFuncName = (litFunc != null) ? litFunc.getName() + " @ " + litFunc.getEntryPoint() : "(no function)";
                    output.append("//   Literal at ROM " + found + " -> LDR from " + litFromAddr + " in " + litFuncName + "\n");
                    if (litFunc != null) {
                        functionsToDecompile.add(litFunc.getEntryPoint().getOffset());
                    }
                    hasCodeRef = true;
                }
                if (!hasCodeRef) {
                    output.append("//   Literal at ROM " + found + " (no code references to this literal)\n");
                }
                literalCount++;
                // Search for next occurrence
                Address nextStart = found.add(4);
                if (nextStart.getOffset() >= 0xFFFFFFFFL) break;
                found = memory.findBytes(nextStart, searchEnd, searchBytes, null, true, monitor);
            }
            if (literalCount == 0) {
                output.append("//   (no ROM literals found containing this address)\n");
            }
            output.append("\n");
        }

        // Method 3: Search for instructions that compute state_base + offset
        // The compiler typically does: LDR Rn, =state_base; then LDR/STR Rm, [Rn, #offset]
        // The offset values 0x114, 0x118, 0x6C would appear as immediate offsets in LDR/STR instructions
        // We need to find instructions that use the state base (loaded from DAT_ff8c2e24)
        // and access at these offsets.
        //
        // Since Ghidra's decompiler handles this, we'll rely on decompilation in Part 2.

        output.append("\n");

        // ============================================================
        // PART 2: Instruction-level scan for offset patterns
        // ============================================================
        output.append("########################################################################\n");
        output.append("# PART 2: ARM Instruction Scan for State Struct Offset Access\n");
        output.append("#\n");
        output.append("# Scanning all ARM instructions in ROM for LDR/STR with offsets\n");
        output.append("# 0x114, 0x118, 0x6C that could access the state struct.\n");
        output.append("# Also scanning for the pointer to state base at DAT_ff8c2e24.\n");
        output.append("########################################################################\n\n");

        // Scan for the literal pool value 0x70D8 (state base itself) — though
        // the code loads it via DAT_ff8c2e24, we should also find where DAT_ff8c2e24
        // stores the state base pointer.
        //
        // More useful: Find all ROM locations that contain the literal 0xFF8C2E24
        // (the address of the pointer to state base). Any function that loads this
        // address can potentially access any offset in the state struct.

        // Instead of that broad approach, let's do a targeted instruction scan
        // in the ROM range looking for instructions with these specific immediate offsets
        // near known state-base-loading code.

        // The most effective approach: scan for ARM instructions of the form
        // LDR/STR Rx, [Ry, #0x114] / #0x118 / #0x6C
        // ARM encoding: LDR Rd, [Rn, #imm12] has imm12 in bits 0-11
        // For offset 0x114: imm12 = 0x114
        // For offset 0x118: imm12 = 0x118
        // For offset 0x6C:  imm12 = 0x06C

        int[] searchOffsets = { 0x114, 0x118, 0x6C };
        String[] searchOffsetNames = { "+0x114", "+0x118", "+0x6C" };

        for (int si = 0; si < searchOffsets.length; si++) {
            int offset = searchOffsets[si];
            output.append("// --- Instructions with immediate offset " + searchOffsetNames[si] + " (0x" + Integer.toHexString(offset) + ") ---\n");

            // ARM LDR Rd, [Rn, #imm12]:  cond_010_P_U_B_W_L_Rn_Rd_imm12
            // For LDR (load): bit 20 = 1, P=1 (pre-indexed), U=1 (add), B=0 (word), W=0
            // Mask: 0x0F_F0_0F_FF for bits we care about: bits 20-27 = 0x59 (LDR pre-index up)
            // Actually simpler: scan instruction text via Ghidra listing

            // Use Ghidra's instruction iterator to find LDR/STR with the right offset
            Address romStart = toAddr(0xFF810000L);
            Address romEnd = toAddr(0xFFFF0000L);
            AddressSet romRange = new AddressSet(romStart, romEnd);
            InstructionIterator instrIter = currentProgram.getListing().getInstructions(romRange, true);
            int instrFound = 0;

            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                String mnemonic = instr.getMnemonicString();
                // Look for LDR and STR instructions
                if (mnemonic.startsWith("ldr") || mnemonic.startsWith("str")) {
                    String instrStr = instr.toString();
                    // Check if the instruction references our offset
                    // ARM assembly format: ldr r0, [r1, #0x114]
                    String hexOffset = "#0x" + Integer.toHexString(offset);
                    if (instrStr.contains(hexOffset) || instrStr.contains("#" + offset)) {
                        Address instrAddr = instr.getAddress();
                        Function func = funcMgr.getFunctionContaining(instrAddr);
                        String funcName = (func != null) ? func.getName() + " @ " + func.getEntryPoint() : "(no function)";
                        output.append("//   " + instrAddr + ": " + instrStr + "  [in " + funcName + "]\n");
                        if (func != null) {
                            functionsToDecompile.add(func.getEntryPoint().getOffset());
                        }
                        instrFound++;
                    }
                }
            }
            if (instrFound == 0) {
                output.append("//   (no instructions found with this immediate offset)\n");
            }
            output.append("\n");
        }

        // ============================================================
        // PART 3: Decompile key functions
        // ============================================================
        output.append("\n########################################################################\n");
        output.append("# PART 3: Decompilation of Key Functions\n");
        output.append("#\n");
        output.append("# Primary targets: pipeline functions + the recording callbacks themselves\n");
        output.append("########################################################################\n\n");

        // Decompile the primary targets first
        for (int i = 0; i < DECOMPILE_TARGETS.length; i++) {
            long addr = DECOMPILE_TARGETS[i];
            String name = DECOMPILE_NAMES[i];
            decompileAndAppend(decomp, output, addr, name);
        }

        // Also decompile any additional functions found via cross-references
        output.append("\n########################################################################\n");
        output.append("# PART 4: Additional Functions Found via Cross-References\n");
        output.append("########################################################################\n\n");

        for (Long addr : functionsToDecompile) {
            // Skip if already in primary targets
            boolean alreadyDone = false;
            for (long target : DECOMPILE_TARGETS) {
                if (target == addr) {
                    alreadyDone = true;
                    break;
                }
            }
            if (alreadyDone) continue;

            Function func = getFunctionAt(toAddr(addr));
            String name = (func != null) ? func.getName() : "FUN_" + Long.toHexString(addr);
            decompileAndAppend(decomp, output, addr, "XREF_" + name);
        }

        // ============================================================
        // PART 5: Summary of offset usage patterns
        // ============================================================
        output.append("\n########################################################################\n");
        output.append("# PART 5: Detailed Offset Analysis Summary\n");
        output.append("#\n");
        output.append("# Based on decompilation, summarize how each offset is used.\n");
        output.append("########################################################################\n\n");

        // Search decompiled output of the big pipeline handler for the offset patterns
        // We already have FUN_ff8c21c8 from Part 3, so we just add analysis notes

        output.append("// Key observations from FUN_ff8c21c8 (the big pipeline handler):\n");
        output.append("//\n");
        output.append("// The function accesses the state struct via DAT_ff8c2e24 (= puVar4 in decompilation).\n");
        output.append("// Look for puVar4 + 0x114, puVar4 + 0x118, puVar4 + 0x6C in the decompiled code above.\n");
        output.append("//\n");
        output.append("// Also check FUN_ff8c2938 which accesses +0x5C and many other offsets.\n");
        output.append("//\n");
        output.append("// Note: The decompiler may show these as byte offsets or word offsets\n");
        output.append("// depending on the variable type used. If puVar4 is byte*, offsets match directly.\n");
        output.append("// If puVar4 is uint*, offsets are divided by 4.\n\n");

        // Write output to file
        String outputPath = "C:/projects/ixus870IS/firmware-analysis/callback_usage_decompiled.txt";
        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\nCallback usage analysis written to: " + outputPath);
        println("Total output length: " + output.length() + " characters");
    }

    private void decompileAndAppend(DecompInterface decomp, StringBuilder output, long addr, String name) {
        Address address = toAddr(addr);
        println("Decompiling " + name + " at " + address + "...");

        Function func = getFunctionAt(address);
        if (func == null) {
            try {
                func = createFunction(address, name);
            } catch (Exception e) {
                output.append("// Could not create function " + name + " at " + address + ": " + e.getMessage() + "\n\n");
                return;
            }
        }
        if (func == null) {
            output.append("// Could not find or create function " + name + " at " + address + "\n\n");
            return;
        }

        // Try to label the function
        try {
            func.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED);
        } catch (Exception e) {
            // Name might already be set or conflict, that's fine
        }

        DecompileResults results = decomp.decompileFunction(func, 120, monitor);
        if (results == null || !results.decompileCompleted()) {
            output.append("// Decompilation failed for " + name + " at " + address + "\n\n");
            return;
        }

        DecompiledFunction decompFunc = results.getDecompiledFunction();
        if (decompFunc == null) {
            output.append("// No decompiled output for " + name + " at " + address + "\n\n");
            return;
        }

        String sig = decompFunc.getSignature();
        String code = decompFunc.getC();

        output.append("// === " + name + " @ " + address + " ===\n");
        output.append("// Signature: " + sig + "\n");
        output.append(code);
        output.append("\n\n");
    }
}
