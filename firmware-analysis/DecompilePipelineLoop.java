// Ghidra headless script to decompile the pipeline task loop functions
// that CHECK +0x5C (DMA request state) at the state struct
//
// Key addresses found by ROM search for LDR Rd, [Rn, #0x5C]:
//   0xFF8C2318 - LDR R0, [R6, #0x5C]  (READ)
//   0xFF8C2620 - LDR R0, [R5, #0x5C]  (READ)
//   0xFF8C28C8 - STR R0, [R5, #0x5C]  (WRITE - sets +0x5C to 5?)
//   0xFF8C2958 - LDR R12, [R5, #0x5C] (READ)
//
// Also: writes around the DMA trigger area
//   0xFF8C41BC - STR R0, [R1, #0x5C]  (WRITE)
//   0xFF8C41EC - STR R0, [R1, #0x5C]  (WRITE)
//   0xFF8C4240 - STR R3, [R2, #0x5C]  (WRITE)
//
// We use getFunctionContaining() to find the enclosing functions.
//
//@category CHDK
//@author webcam-re

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.address.Address;
import java.io.FileWriter;
import java.util.LinkedHashSet;
import java.util.Set;

public class DecompilePipelineLoop extends GhidraScript {

    // Addresses where +0x5C is accessed (from ROM search)
    private static final long[] TARGET_ADDRS = {
        0xFF8C2318L, // LDR R0, [R6, #0x5C]
        0xFF8C2620L, // LDR R0, [R5, #0x5C]
        0xFF8C28C8L, // STR R0, [R5, #0x5C]
        0xFF8C2958L, // LDR R12, [R5, #0x5C]
        0xFF8C41BCL, // STR R0, [R1, #0x5C]
        0xFF8C41ECL, // STR R0, [R1, #0x5C]
        0xFF8C4240L, // STR R3, [R2, #0x5C]
    };

    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        FunctionManager funcMgr = currentProgram.getFunctionManager();

        StringBuilder output = new StringBuilder();
        output.append("========================================================================\n");
        output.append("Pipeline Loop Functions that access +0x5C\n");
        output.append("Firmware: IXUS 870 IS / SD 880 IS, version 1.01a\n");
        output.append("Purpose: Find the code that checks +0x5C==3 and triggers VRAM DMA\n");
        output.append("========================================================================\n\n");

        // Collect unique functions containing the target addresses
        Set<Long> decompiled = new LinkedHashSet<>();

        for (long targetAddr : TARGET_ADDRS) {
            Address addr = toAddr(targetAddr);
            Function func = funcMgr.getFunctionContaining(addr);

            if (func == null) {
                output.append("// No function found containing 0x" +
                    Long.toHexString(targetAddr).toUpperCase() + "\n");
                // Try to create a function at a nearby aligned address
                // Search backwards for a function entry
                for (long probe = targetAddr & ~3L; probe > targetAddr - 0x200; probe -= 4) {
                    Address probeAddr = toAddr(probe);
                    func = funcMgr.getFunctionContaining(probeAddr);
                    if (func != null) break;
                    func = getFunctionAt(probeAddr);
                    if (func != null) break;
                }
                if (func == null) {
                    output.append("// Could not find enclosing function for 0x" +
                        Long.toHexString(targetAddr).toUpperCase() + "\n\n");
                    continue;
                }
            }

            long funcEntry = func.getEntryPoint().getOffset() & 0xFFFFFFFFL;
            if (decompiled.contains(funcEntry)) {
                output.append("// 0x" + Long.toHexString(targetAddr).toUpperCase() +
                    " is in already-decompiled function at 0x" +
                    Long.toHexString(funcEntry).toUpperCase() + "\n\n");
                continue;
            }
            decompiled.add(funcEntry);

            String name = func.getName();
            println("Decompiling " + name + " at " + func.getEntryPoint() +
                " (contains 0x" + Long.toHexString(targetAddr).toUpperCase() + ")...");

            DecompileResults results = decomp.decompileFunction(func, 120, monitor);
            if (results == null || !results.decompileCompleted()) {
                output.append("// Decompilation failed for " + name + " at " + func.getEntryPoint() + "\n\n");
                continue;
            }

            DecompiledFunction decompFunc = results.getDecompiledFunction();
            if (decompFunc == null) {
                output.append("// No decompiled output for " + name + " at " + func.getEntryPoint() + "\n\n");
                continue;
            }

            output.append("// === " + name + " @ " + func.getEntryPoint() +
                " (contains +0x5C access at 0x" + Long.toHexString(targetAddr).toUpperCase() + ") ===\n");
            output.append("// Signature: " + decompFunc.getSignature() + "\n");
            output.append(decompFunc.getC());
            output.append("\n\n\n");
        }

        String outputPath = "C:/projects/ixus870IS/firmware-analysis/pipeline_loop_decompiled.txt";
        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\nDecompilation output written to: " + outputPath);
        println("\n" + output.toString());
    }
}
