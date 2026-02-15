// Ghidra headless script to decompile FUN_ff8c1fe4_PipelineFrameCallback
// and trace the origin of param_4 passed to FUN_ff9e5328_FrameProcessing.
//
// Run with: analyzeHeadless <project_dir> <project_name> -process PRIMARY.BIN -noanalysis
//           -scriptPath <dir> -postScript DecompilePipelineCallback.java
//
//@category CHDK
//@author webcam-re

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Data;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.mem.Memory;
import java.io.FileWriter;
import java.io.File;
import java.util.LinkedHashSet;
import java.util.Set;

public class DecompilePipelineCallback extends GhidraScript {

    // Primary targets
    private static final long[] PRIMARY_ADDRS = {
        0xFF8C1FE4L,  // FUN_ff8c1fe4_PipelineFrameCallback
        0xFF9E5328L,  // FUN_ff9e5328_FrameProcessing
    };

    private static final String[] PRIMARY_NAMES = {
        "FUN_ff8c1fe4_PipelineFrameCallback",
        "FUN_ff9e5328_FrameProcessing",
    };

    // Functions called by FUN_ff8c1fe4 or between it and FUN_ff9e5328
    // These will be discovered dynamically, but we also add known candidates
    private static final long[] HELPER_ADDRS = {
        0xFF8C3BFCL,  // sub_FF8C3BFC - Recording pipeline setup (called by movie_record_task)
        0xFF8C4208L,  // FUN_ff8c4208 - DMA trigger function
        0xFF9E8190L,  // FUN_ff9e8190 - JPCORE enable
        0xFF92FE8CL,  // sub_FF92FE8C - Movie frame getter (4 output pointers)
        0xFF8C4288L,  // FUN_ff8c4288 - MJPEG active check
        0xFF8C2ED8L,  // FUN_ff8c2ed8 - called by StartEVFMovVGA_setup
        0xFF8C4C60L,  // FUN_ff8c4c60 - called at start of StartEVFMovVGA
    };

    private static final String[] HELPER_NAMES = {
        "sub_FF8C3BFC_RecPipelineSetup",
        "FUN_ff8c4208_DMATrigger",
        "FUN_ff9e8190_JPCOREEnable",
        "sub_FF92FE8C_MovieFrameGetter",
        "FUN_ff8c4288_MjpegActiveCheck",
        "FUN_ff8c2ed8_EVFSetupHelper",
        "FUN_ff8c4c60_EVFPreSetup",
    };

    private DecompInterface decomp;
    private StringBuilder output;
    private Set<Long> decompiled = new LinkedHashSet<>();

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        output = new StringBuilder();
        output.append("========================================================================\n");
        output.append("Pipeline Frame Callback Decompilation — param_4 Trace\n");
        output.append("Firmware: IXUS 870 IS / SD 880 IS, version 1.01a\n");
        output.append("========================================================================\n\n");

        // --- Part 1: Decompile the primary targets ---
        output.append("################################################################\n");
        output.append("# PART 1: PRIMARY TARGETS\n");
        output.append("################################################################\n\n");

        for (int i = 0; i < PRIMARY_ADDRS.length; i++) {
            decompileFunc(PRIMARY_ADDRS[i], PRIMARY_NAMES[i]);
        }

        // --- Part 2: Find all functions called BY FUN_ff8c1fe4 ---
        output.append("\n################################################################\n");
        output.append("# PART 2: FUNCTIONS CALLED BY FUN_ff8c1fe4_PipelineFrameCallback\n");
        output.append("################################################################\n\n");

        Address pipelineAddr = toAddr(0xFF8C1FE4L);
        Function pipelineFunc = getFunctionAt(pipelineAddr);
        if (pipelineFunc != null) {
            Set<Function> calledFuncs = pipelineFunc.getCalledFunctions(monitor);
            for (Function called : calledFuncs) {
                long addr = called.getEntryPoint().getOffset();
                if (!decompiled.contains(addr)) {
                    decompileFunc(addr, called.getName() + "_calledByPipeline");
                }
            }
        }

        // --- Part 3: Find all functions called BY FUN_ff9e5328 ---
        output.append("\n################################################################\n");
        output.append("# PART 3: FUNCTIONS CALLED BY FUN_ff9e5328_FrameProcessing\n");
        output.append("################################################################\n\n");

        Address frameProcessingAddr = toAddr(0xFF9E5328L);
        Function frameProcessingFunc = getFunctionAt(frameProcessingAddr);
        if (frameProcessingFunc != null) {
            Set<Function> calledFuncs = frameProcessingFunc.getCalledFunctions(monitor);
            for (Function called : calledFuncs) {
                long addr = called.getEntryPoint().getOffset();
                if (!decompiled.contains(addr)) {
                    decompileFunc(addr, called.getName() + "_calledByFrameProc");
                }
            }
        }

        // --- Part 4: Find all CALLERS of FUN_ff8c1fe4 (where does the callback come from?) ---
        output.append("\n################################################################\n");
        output.append("# PART 4: CALLERS OF FUN_ff8c1fe4 (cross-references)\n");
        output.append("################################################################\n\n");

        if (pipelineFunc != null) {
            Set<Function> callingFuncs = pipelineFunc.getCallingFunctions(monitor);
            output.append("// Found " + callingFuncs.size() + " callers of FUN_ff8c1fe4:\n");
            for (Function caller : callingFuncs) {
                output.append("//   - " + caller.getName() + " @ " + caller.getEntryPoint() + "\n");
            }
            output.append("\n");

            for (Function caller : callingFuncs) {
                long addr = caller.getEntryPoint().getOffset();
                if (!decompiled.contains(addr)) {
                    decompileFunc(addr, caller.getName() + "_callerOfPipeline");
                }
            }
        }

        // Also find references TO the address 0xFF8C1FE4 (may be used as function pointer)
        output.append("\n// --- References TO address 0xFF8C1FE4 (function pointer usage) ---\n");
        ReferenceIterator refIter = currentProgram.getReferenceManager().getReferencesTo(toAddr(0xFF8C1FE4L));
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            Address fromAddr = ref.getFromAddress();
            output.append("//   Ref from " + fromAddr + " (type: " + ref.getReferenceType() + ")\n");
            // Try to find the containing function and decompile it
            Function containingFunc = getFunctionContaining(fromAddr);
            if (containingFunc != null) {
                long addr = containingFunc.getEntryPoint().getOffset();
                output.append("//   -> In function: " + containingFunc.getName() + " @ " + containingFunc.getEntryPoint() + "\n");
                if (!decompiled.contains(addr)) {
                    decompileFunc(addr, containingFunc.getName() + "_refsToPipeline");
                }
            }
        }

        // --- Part 5: Find all CALLERS of FUN_ff9e5328 ---
        output.append("\n################################################################\n");
        output.append("# PART 5: ALL CALLERS OF FUN_ff9e5328_FrameProcessing\n");
        output.append("################################################################\n\n");

        if (frameProcessingFunc != null) {
            Set<Function> callingFuncs = frameProcessingFunc.getCallingFunctions(monitor);
            output.append("// Found " + callingFuncs.size() + " callers of FUN_ff9e5328:\n");
            for (Function caller : callingFuncs) {
                output.append("//   - " + caller.getName() + " @ " + caller.getEntryPoint() + "\n");
            }
            output.append("\n");

            for (Function caller : callingFuncs) {
                long addr = caller.getEntryPoint().getOffset();
                if (!decompiled.contains(addr)) {
                    decompileFunc(addr, caller.getName() + "_callerOfFrameProc");
                }
            }
        }

        // --- Part 6: Decompile known helper/pipeline functions ---
        output.append("\n################################################################\n");
        output.append("# PART 6: KNOWN HELPER / PIPELINE FUNCTIONS\n");
        output.append("################################################################\n\n");

        for (int i = 0; i < HELPER_ADDRS.length; i++) {
            if (!decompiled.contains(HELPER_ADDRS[i])) {
                decompileFunc(HELPER_ADDRS[i], HELPER_NAMES[i]);
            }
        }

        // --- Part 7: Resolve DAT_ references ---
        output.append("\n################################################################\n");
        output.append("# PART 7: DAT_ / GLOBAL DATA REFERENCES\n");
        output.append("################################################################\n\n");

        // Key known data addresses from existing analysis + likely ones near ff8c1fe4
        long[] dataAddrs = {
            0xFF8C2E24L, // DAT_ff8c2e24 - MJPEG state structure base
            0xFF8C3D04L, // DAT_ff8c3d04 - Used by GetMovieJpegVRAMHPixelsSize/VPixelsSize
            0xFF8C43F4L, // DAT_ff8c43f4 - Used by StopContinuousVRAMData
            0xFFAA1BB8L, // DAT_ffaa1bb8 - Event flag handle
            0xFFAA2314L, // DAT_ffaa2314 - VRAM buffer address
            0xFFAA2318L, // DAT_ffaa2318 - VRAM buffer max size
            0xFF9E8A00L, // DAT_ff9e8a00 - EVF event flag
            0xFF9E8A04L, // DAT_ff9e8a04 - EVF timeout
            0xFF9E8F30L, // DAT_ff9e8f30 - XGA/HD callback
        };

        Memory mem = currentProgram.getMemory();
        for (long addr : dataAddrs) {
            try {
                Address a = toAddr(addr);
                int val = mem.getInt(a);
                output.append(String.format("// DAT_%08x = 0x%08X (%d)\n", addr, val, val));
            } catch (Exception e) {
                output.append(String.format("// DAT_%08x = <unreadable: %s>\n", addr, e.getMessage()));
            }
        }

        // Scan for DAT_ addresses referenced in the range around ff8c1fe4
        output.append("\n// --- Scanning data references near FUN_ff8c1fe4 (ff8c1f00..ff8c2200) ---\n");
        Address scanStart = toAddr(0xFF8C1F00L);
        Address scanEnd = toAddr(0xFF8C2200L);
        Instruction instr = getInstructionAt(scanStart);
        if (instr == null) {
            instr = getInstructionAfter(scanStart);
        }
        while (instr != null && instr.getAddress().compareTo(scanEnd) < 0) {
            Reference[] refs = instr.getReferencesFrom();
            for (Reference ref : refs) {
                Address toA = ref.getToAddress();
                long toOff = toA.getOffset();
                // Only report references to RAM (0x00000000-0x03FFFFFF) or data in ROM
                if (toOff < 0x04000000L || (toOff >= 0x40000000L && toOff < 0x50000000L) ||
                    (toOff >= 0xC0000000L && toOff < 0xD0000000L)) {
                    output.append(String.format("//   %s: refs -> 0x%08X (%s)\n",
                        instr.getAddress(), toOff, ref.getReferenceType()));
                } else if (toOff >= 0xFF800000L) {
                    // ROM data reference
                    try {
                        int val = mem.getInt(toA);
                        output.append(String.format("//   %s: refs -> 0x%08X [ROM data = 0x%08X]\n",
                            instr.getAddress(), toOff, val));
                    } catch (Exception e) {
                        // skip
                    }
                }
            }
            instr = getInstructionAfter(instr.getAddress());
        }

        // --- Part 8: Scan for data near FUN_ff9e5328 ---
        output.append("\n// --- Scanning data references near FUN_ff9e5328 (ff9e5300..ff9e5500) ---\n");
        scanStart = toAddr(0xFF9E5300L);
        scanEnd = toAddr(0xFF9E5500L);
        instr = getInstructionAt(scanStart);
        if (instr == null) {
            instr = getInstructionAfter(scanStart);
        }
        while (instr != null && instr.getAddress().compareTo(scanEnd) < 0) {
            Reference[] refs = instr.getReferencesFrom();
            for (Reference ref : refs) {
                Address toA = ref.getToAddress();
                long toOff = toA.getOffset();
                if (toOff < 0x04000000L || (toOff >= 0x40000000L && toOff < 0x50000000L) ||
                    (toOff >= 0xC0000000L && toOff < 0xD0000000L)) {
                    output.append(String.format("//   %s: refs -> 0x%08X (%s)\n",
                        instr.getAddress(), toOff, ref.getReferenceType()));
                } else if (toOff >= 0xFF800000L) {
                    try {
                        int val = mem.getInt(toA);
                        output.append(String.format("//   %s: refs -> 0x%08X [ROM data = 0x%08X]\n",
                            instr.getAddress(), toOff, val));
                    } catch (Exception e) {
                        // skip
                    }
                }
            }
            instr = getInstructionAfter(instr.getAddress());
        }

        // --- Part 9: Disassembly listing for key areas ---
        output.append("\n################################################################\n");
        output.append("# PART 9: RAW DISASSEMBLY — FUN_ff8c1fe4 region\n");
        output.append("################################################################\n\n");

        dumpDisassembly(0xFF8C1FE4L, 80);

        output.append("\n// --- RAW DISASSEMBLY — FUN_ff9e5328 region ---\n\n");
        dumpDisassembly(0xFF9E5328L, 80);

        // Write output to file
        String outputPath = "C:/projects/ixus870IS/firmware-analysis/pipeline_callback_decompiled.txt";

        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\nDecompilation output written to: " + outputPath);
        println("\n" + output.toString());
    }

    private void decompileFunc(long addr, String label) {
        decompiled.add(addr);
        Address address = toAddr(addr);
        println("Decompiling " + label + " at " + address + "...");

        Function func = getFunctionAt(address);
        if (func == null) {
            try {
                func = createFunction(address, label);
            } catch (Exception e) {
                output.append(String.format("// Could not create function %s at 0x%08X: %s\n\n", label, addr, e.getMessage()));
                return;
            }
        }
        if (func == null) {
            output.append(String.format("// Could not find or create function %s at 0x%08X\n\n", label, addr));
            return;
        }

        try {
            func.setName(label, ghidra.program.model.symbol.SourceType.USER_DEFINED);
        } catch (Exception e) {
            // Name collision — use existing name
        }

        DecompileResults results = decomp.decompileFunction(func, 120, monitor);
        if (results == null || !results.decompileCompleted()) {
            output.append(String.format("// Decompilation failed for %s at 0x%08X\n\n", label, addr));
            return;
        }

        DecompiledFunction decompFunc = results.getDecompiledFunction();
        if (decompFunc == null) {
            output.append(String.format("// No decompiled output for %s at 0x%08X\n\n", label, addr));
            return;
        }

        String sig = decompFunc.getSignature();
        String code = decompFunc.getC();

        output.append(String.format("// === %s @ 0x%08X ===\n", label, addr));
        output.append("// Signature: " + sig + "\n");
        output.append(code);
        output.append("\n\n");
    }

    private void dumpDisassembly(long startAddr, int count) {
        Address addr = toAddr(startAddr);
        Instruction instr = getInstructionAt(addr);
        if (instr == null) {
            instr = getInstructionAfter(addr);
        }
        for (int i = 0; i < count && instr != null; i++) {
            StringBuilder line = new StringBuilder();
            line.append(String.format("  %s:  ", instr.getAddress()));
            // Get instruction length for alignment
            int instrLen = instr.getLength();
            line.append(String.format("[%d bytes] ", instrLen));
            // Pad to align mnemonics
            while (line.length() < 28) {
                line.append(' ');
            }
            line.append(instr.toString());

            // Add operand references as comments
            Reference[] refs = instr.getReferencesFrom();
            for (Reference ref : refs) {
                if (ref.getReferenceType().isData()) {
                    Address toA = ref.getToAddress();
                    try {
                        Memory mem = currentProgram.getMemory();
                        int val = mem.getInt(toA);
                        line.append(String.format("  ; [%s] = 0x%08X", toA, val));
                    } catch (Exception e) {
                        // skip
                    }
                }
            }

            output.append(line.toString() + "\n");
            instr = getInstructionAfter(instr.getAddress());
        }
    }
}
