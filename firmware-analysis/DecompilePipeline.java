// Ghidra headless script to decompile recording pipeline functions
// Targets: sub_FF8C3BFC (RecordingPipelineSetup), FUN_ff8c4208 (DMA trigger),
// FUN_ff9e8190 (JPCORE enable), sub_FF92FE8C (movie frame getter),
// plus cross-reference scan for functions writing to PS3[4] at 0x8234.
//
// Run with: analyzeHeadless <project_dir> <project_name> -process PRIMARY.BIN -noanalysis
//           -scriptPath <dir> -postScript DecompilePipeline.java
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
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import java.io.FileWriter;
import java.io.File;
import java.util.ArrayList;
import java.util.HashSet;

public class DecompilePipeline extends GhidraScript {

    // Primary target functions to decompile
    private static final long[] PRIMARY_ADDRS = {
        0xFF8C3BFCL, // sub_FF8C3BFC - RecordingPipelineSetup (called by movie_record_task)
        0xFF8C4208L, // FUN_ff8c4208 - DMA trigger function (sets up one-shot DMA capture)
        0xFF9E8190L, // FUN_ff9e8190 - JPCORE enable (called by StartMjpegMaking_inner)
        0xFF9E81A0L, // FUN_ff9e81a0 - JPCORE disable (called by StopMjpegMaking_inner)
        0xFF92FE8CL, // sub_FF92FE8C - Movie frame getter (4 output pointers, used during recording)
        0xFF8C4288L, // FUN_ff8c4288 - MjpegActiveCheck (returns 1 if MJPEG engine is active)
        0xFF8C2ED8L, // FUN_ff8c2ed8 - Called by FUN_ff8c3c64 (StartEVFMovVGA_setup)
        0xFF8C4C60L, // FUN_ff8c4c60 - Called at start of StartEVFMovVGA
        0xFF8C391CL, // FUN_ff8c391c - Called by StopEVF_FW
    };

    private static final String[] PRIMARY_NAMES = {
        "sub_FF8C3BFC_RecordingPipelineSetup",
        "FUN_ff8c4208_DMA_Trigger",
        "FUN_ff9e8190_JPCORE_Enable",
        "FUN_ff9e81a0_JPCORE_Disable",
        "sub_FF92FE8C_MovieFrameGetter",
        "FUN_ff8c4288_MjpegActiveCheck",
        "FUN_ff8c2ed8_EVFSetupInner",
        "FUN_ff8c4c60_EVFPreSetup",
        "FUN_ff8c391c_StopEVFInner",
    };

    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        StringBuilder output = new StringBuilder();
        output.append("========================================================================\n");
        output.append("Recording Pipeline Function Decompilation\n");
        output.append("Firmware: IXUS 870 IS / SD 880 IS, version 1.01a\n");
        output.append("========================================================================\n\n");

        // === Part 1: Decompile primary target functions ===
        output.append("########################################################################\n");
        output.append("# PART 1: Primary Target Functions\n");
        output.append("########################################################################\n\n");

        // Track all function addresses we've decompiled to avoid duplicates
        HashSet<Long> decompiled = new HashSet<>();

        for (int i = 0; i < PRIMARY_ADDRS.length; i++) {
            decompileAndAppend(decomp, output, PRIMARY_ADDRS[i], PRIMARY_NAMES[i], decompiled);
        }

        // === Part 2: Cross-reference scan for writes to 0x8234 (PS3[4]) ===
        output.append("########################################################################\n");
        output.append("# PART 2: Cross-Reference Scan for PS3[4] at 0x8234\n");
        output.append("#\n");
        output.append("# Scanning for firmware functions that reference address 0x8234\n");
        output.append("# (PipelineStep3 offset +0x10 = JPCORE_DMA_Start result).\n");
        output.append("# Also scanning 0x8224 (PS3 base) and 0x8230 (PS3 completion mask).\n");
        output.append("########################################################################\n\n");

        // Scan for references to key PS3 addresses
        long[] scanAddrs = { 0x8224L, 0x8230L, 0x8234L, 0x8238L, 0x823CL };
        String[] scanNames = { "PS3_Base", "PS3_CompletionMask", "PS3_JPCORE_DMA_Start",
                               "PS3_Step2Flag", "PS3_Step3Flag" };

        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        ArrayList<Long> xrefFuncAddrs = new ArrayList<>();
        ArrayList<String> xrefFuncNames = new ArrayList<>();

        for (int s = 0; s < scanAddrs.length; s++) {
            Address targetAddr = toAddr(scanAddrs[s]);
            output.append("// --- References to " + scanNames[s] + " (0x" +
                          Long.toHexString(scanAddrs[s]) + ") ---\n");

            ReferenceIterator refIter = refMgr.getReferencesTo(targetAddr);
            int refCount = 0;
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                Function containingFunc = funcMgr.getFunctionContaining(fromAddr);
                String funcName = (containingFunc != null) ?
                    containingFunc.getName() + " @ " + containingFunc.getEntryPoint() :
                    "(no function)";
                output.append("//   Ref from " + fromAddr + " in " + funcName +
                              " [" + ref.getReferenceType() + "]\n");
                refCount++;

                // Queue containing function for decompilation if not already done
                if (containingFunc != null) {
                    long entryAddr = containingFunc.getEntryPoint().getOffset();
                    if (!decompiled.contains(entryAddr)) {
                        boolean alreadyQueued = false;
                        for (Long q : xrefFuncAddrs) {
                            if (q == entryAddr) { alreadyQueued = true; break; }
                        }
                        if (!alreadyQueued) {
                            xrefFuncAddrs.add(entryAddr);
                            xrefFuncNames.add("XREF_" + scanNames[s] + "_" +
                                              containingFunc.getName());
                        }
                    }
                }
            }
            if (refCount == 0) {
                output.append("//   (no direct references found)\n");
            }
            output.append("\n");
        }

        // Also scan for the PS3 base literal in ROM literal pools.
        // Firmware often loads a base pointer from a literal pool, then
        // accesses offsets. Search ROM for the value 0x00008224.
        output.append("// --- ROM literal pool scan for 0x00008224 (PS3 base) ---\n");
        try {
            Address romStart = toAddr(0xFF810000L);
            Address romEnd = toAddr(0xFFFFFFFFL);
            byte[] pattern = { 0x24, (byte)0x82, 0x00, 0x00 }; // little-endian 0x00008224
            Address found = currentProgram.getMemory().findBytes(romStart, romEnd, pattern, null, true, monitor);
            int litCount = 0;
            while (found != null && litCount < 20) {
                Function containingFunc = funcMgr.getFunctionContaining(found);
                String ctx = (containingFunc != null) ?
                    "in " + containingFunc.getName() + " @ " + containingFunc.getEntryPoint() :
                    "(data/literal pool)";
                output.append("//   Literal 0x00008224 at ROM " + found + " " + ctx + "\n");
                litCount++;

                // Also check references TO this literal pool address (LDR instructions)
                ReferenceIterator litRefs = refMgr.getReferencesTo(found);
                while (litRefs.hasNext()) {
                    Reference lr = litRefs.next();
                    Address lrFrom = lr.getFromAddress();
                    Function lrFunc = funcMgr.getFunctionContaining(lrFrom);
                    if (lrFunc != null) {
                        long entryAddr = lrFunc.getEntryPoint().getOffset();
                        output.append("//     -> LDR from " + lrFrom + " in " +
                                      lrFunc.getName() + " @ " + lrFunc.getEntryPoint() + "\n");
                        if (!decompiled.contains(entryAddr)) {
                            boolean alreadyQueued = false;
                            for (Long q : xrefFuncAddrs) {
                                if (q == entryAddr) { alreadyQueued = true; break; }
                            }
                            if (!alreadyQueued) {
                                xrefFuncAddrs.add(entryAddr);
                                xrefFuncNames.add("XREF_PS3Literal_" + lrFunc.getName());
                            }
                        }
                    }
                }

                // Search for next occurrence
                Address nextStart = found.add(4);
                if (nextStart.compareTo(romEnd) >= 0) break;
                found = currentProgram.getMemory().findBytes(nextStart, romEnd, pattern, null, true, monitor);
            }
            if (litCount == 0) {
                output.append("//   (no literal pool occurrences found)\n");
            }
        } catch (Exception e) {
            output.append("//   Error during literal scan: " + e.getMessage() + "\n");
        }
        output.append("\n");

        // Also scan for 0x00002554 (JPCORE state struct base) in ROM
        output.append("// --- ROM literal pool scan for 0x00002554 (JPCORE state base) ---\n");
        try {
            Address romStart = toAddr(0xFF810000L);
            Address romEnd = toAddr(0xFFFFFFFFL);
            byte[] pattern = { 0x54, 0x25, 0x00, 0x00 }; // little-endian 0x00002554
            Address found = currentProgram.getMemory().findBytes(romStart, romEnd, pattern, null, true, monitor);
            int litCount = 0;
            while (found != null && litCount < 20) {
                Function containingFunc = funcMgr.getFunctionContaining(found);
                String ctx = (containingFunc != null) ?
                    "in " + containingFunc.getName() + " @ " + containingFunc.getEntryPoint() :
                    "(data/literal pool)";
                output.append("//   Literal 0x00002554 at ROM " + found + " " + ctx + "\n");
                litCount++;

                ReferenceIterator litRefs = refMgr.getReferencesTo(found);
                while (litRefs.hasNext()) {
                    Reference lr = litRefs.next();
                    Address lrFrom = lr.getFromAddress();
                    Function lrFunc = funcMgr.getFunctionContaining(lrFrom);
                    if (lrFunc != null) {
                        long entryAddr = lrFunc.getEntryPoint().getOffset();
                        output.append("//     -> LDR from " + lrFrom + " in " +
                                      lrFunc.getName() + " @ " + lrFunc.getEntryPoint() + "\n");
                        if (!decompiled.contains(entryAddr)) {
                            boolean alreadyQueued = false;
                            for (Long q : xrefFuncAddrs) {
                                if (q == entryAddr) { alreadyQueued = true; break; }
                            }
                            if (!alreadyQueued) {
                                xrefFuncAddrs.add(entryAddr);
                                xrefFuncNames.add("XREF_JPCORELiteral_" + lrFunc.getName());
                            }
                        }
                    }
                }

                Address nextStart = found.add(4);
                if (nextStart.compareTo(romEnd) >= 0) break;
                found = currentProgram.getMemory().findBytes(nextStart, romEnd, pattern, null, true, monitor);
            }
            if (litCount == 0) {
                output.append("//   (no literal pool occurrences found)\n");
            }
        } catch (Exception e) {
            output.append("//   Error during literal scan: " + e.getMessage() + "\n");
        }
        output.append("\n");

        // Decompile all functions found via cross-references
        if (!xrefFuncAddrs.isEmpty()) {
            output.append("// === Decompiling " + xrefFuncAddrs.size() +
                          " functions found via cross-references ===\n\n");
            for (int i = 0; i < xrefFuncAddrs.size(); i++) {
                decompileAndAppend(decomp, output, xrefFuncAddrs.get(i),
                                   xrefFuncNames.get(i), decompiled);
            }
        }

        // === Part 3: Decompile functions called BY sub_FF8C3BFC ===
        // We'll check what sub_FF8C3BFC calls and decompile those too
        output.append("########################################################################\n");
        output.append("# PART 3: Functions Called by sub_FF8C3BFC (RecordingPipelineSetup)\n");
        output.append("########################################################################\n\n");

        Address pipelineAddr = toAddr(0xFF8C3BFCL);
        Function pipelineFunc = getFunctionAt(pipelineAddr);
        if (pipelineFunc == null) {
            pipelineFunc = createFunction(pipelineAddr, "sub_FF8C3BFC_RecordingPipelineSetup");
        }
        if (pipelineFunc != null) {
            // Get all functions called by sub_FF8C3BFC
            AddressSetView body = pipelineFunc.getBody();
            InstructionIterator instIter = currentProgram.getListing().getInstructions(body, true);
            output.append("// Call targets from sub_FF8C3BFC:\n");
            while (instIter.hasNext()) {
                Instruction inst = instIter.next();
                String mnemonic = inst.getMnemonicString();
                if (mnemonic.equals("BL") || mnemonic.equals("bl")) {
                    Reference[] refs = inst.getReferencesFrom();
                    for (Reference ref : refs) {
                        Address callTarget = ref.getToAddress();
                        long callAddr = callTarget.getOffset();
                        Function calledFunc = funcMgr.getFunctionContaining(callTarget);
                        String calledName = (calledFunc != null) ? calledFunc.getName() : "unknown";
                        output.append("//   BL " + callTarget + " (" + calledName + ")" +
                                      " from " + inst.getAddress() + "\n");

                        // Decompile if not already done
                        if (!decompiled.contains(callAddr)) {
                            decompileAndAppend(decomp, output, callAddr,
                                "CalledBy_PipelineSetup_" + calledName, decompiled);
                        }
                    }
                }
            }
            output.append("\n");
        } else {
            output.append("// ERROR: Could not find or create function at 0xFF8C3BFC\n\n");
        }

        // === Part 4: Functions called BY FUN_ff8c4208 (DMA Trigger) ===
        output.append("########################################################################\n");
        output.append("# PART 4: Functions Called by FUN_ff8c4208 (DMA Trigger)\n");
        output.append("########################################################################\n\n");

        Address dmaAddr = toAddr(0xFF8C4208L);
        Function dmaFunc = getFunctionAt(dmaAddr);
        if (dmaFunc == null) {
            dmaFunc = createFunction(dmaAddr, "FUN_ff8c4208_DMA_Trigger");
        }
        if (dmaFunc != null) {
            AddressSetView dmaBody = dmaFunc.getBody();
            InstructionIterator dmaInstIter = currentProgram.getListing().getInstructions(dmaBody, true);
            output.append("// Call targets from FUN_ff8c4208:\n");
            while (dmaInstIter.hasNext()) {
                Instruction inst = dmaInstIter.next();
                String mnemonic = inst.getMnemonicString();
                if (mnemonic.equals("BL") || mnemonic.equals("bl")) {
                    Reference[] refs = inst.getReferencesFrom();
                    for (Reference ref : refs) {
                        Address callTarget = ref.getToAddress();
                        long callAddr = callTarget.getOffset();
                        Function calledFunc = funcMgr.getFunctionContaining(callTarget);
                        String calledName = (calledFunc != null) ? calledFunc.getName() : "unknown";
                        output.append("//   BL " + callTarget + " (" + calledName + ")" +
                                      " from " + inst.getAddress() + "\n");

                        if (!decompiled.contains(callAddr)) {
                            decompileAndAppend(decomp, output, callAddr,
                                "CalledBy_DMATrigger_" + calledName, decompiled);
                        }
                    }
                }
            }
            output.append("\n");
        }

        // Write output to file
        String outputPath = "C:/projects/ixus870IS/firmware-analysis/pipeline_decompiled.txt";

        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\nDecompilation output written to: " + outputPath);
        println("\n" + output.toString());
    }

    /**
     * Decompile a function at the given address and append to output.
     * Tracks decompiled addresses to avoid duplicates.
     */
    private void decompileAndAppend(DecompInterface decomp, StringBuilder output,
                                     long addr, String name, HashSet<Long> decompiled)
            throws Exception {
        if (decompiled.contains(addr)) {
            output.append("// (already decompiled " + name + " @ " +
                          String.format("0x%08X", addr) + ")\n\n");
            return;
        }
        decompiled.add(addr);

        Address address = toAddr(addr);
        println("Decompiling " + name + " at " + address + "...");

        Function func = getFunctionAt(address);
        if (func == null) {
            func = createFunction(address, name);
        }
        if (func == null) {
            output.append("// Could not find or create function " + name + " at " + address + "\n\n");
            return;
        }

        // Label the function (only if it doesn't have a user-defined name already)
        try {
            if (func.getName().startsWith("FUN_") || func.getName().startsWith("sub_")) {
                func.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED);
            }
        } catch (Exception e) {
            // Ignore naming errors
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
