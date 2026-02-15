// Ghidra headless script to decompile the +0x5C state machine function
// and key helper functions that process the VRAM DMA request.
//
// The function at 0xFF8C21C8 is a 1900-byte state machine function that
// contains a switch on +0x5C (cases 0-4). It was not automatically
// identified by Ghidra, so we force-create it.
//
// Case 3 (at 0xFF8C2870) is where the VRAM DMA request should be handled.
// Case 4 (at 0xFF8C28C4) sets +0x5C=5 and signals semaphore at +0xB8.
//
// Also decompile helper functions:
//   FUN_ff9e79c8 — Frame source/dest configuration (called by FUN_ff8c2938)
//   FUN_ff9e5adc — Post-processing metadata (called after frame setup)
//   FUN_ff8ef950 — Pipeline slot trigger (called with different slot IDs)
//   FUN_ff836e74 — Pipeline starter (creates frame callback chain)
//   FUN_ffad3d98 — Ring buffer index function (called frequently)
//   FUN_ff827584 — Semaphore signal (called in case 4)
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
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import java.io.FileWriter;
import java.util.LinkedHashSet;
import java.util.Set;

public class DecompileStateMachine extends GhidraScript {

    // Functions to decompile — entry addresses
    private static final long[][] TARGETS = {
        // {address, forceCreate} — forceCreate=1 means createFunction if missing
        {0xFF8C21C8L, 1}, // State machine with +0x5C switch (PUSH found at this addr)
        {0xFF9E79C8L, 0}, // Frame source/dest config (called by FUN_ff8c2938)
        {0xFF9E5ADCL, 0}, // Post-processing metadata
        {0xFF8EF950L, 0}, // Pipeline slot trigger
        {0xFFAD3D98L, 0}, // Ring buffer index
        {0xFF827584L, 0}, // Semaphore signal
        {0xFF8C1FE4L, 0}, // Pipeline frame callback
    };

    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        FunctionManager funcMgr = currentProgram.getFunctionManager();

        StringBuilder output = new StringBuilder();
        output.append("========================================================================\n");
        output.append("+0x5C State Machine and Helper Functions\n");
        output.append("Firmware: IXUS 870 IS / SD 880 IS, version 1.01a\n");
        output.append("Purpose: Understand the full DMA request handling for VRAM buffer\n");
        output.append("========================================================================\n\n");

        Set<Long> decompiled = new LinkedHashSet<>();

        for (long[] target : TARGETS) {
            long addr = target[0];
            boolean forceCreate = target[1] == 1;

            Address funcAddr = toAddr(addr);
            Function func = funcMgr.getFunctionAt(funcAddr);

            if (func == null) {
                func = funcMgr.getFunctionContaining(funcAddr);
            }

            if (func == null && forceCreate) {
                output.append("// Creating function at 0x" +
                    Long.toHexString(addr).toUpperCase() + "...\n");
                println("Creating function at " + funcAddr + "...");
                try {
                    func = createFunction(funcAddr, "FUN_" +
                        Long.toHexString(addr).toLowerCase());
                    if (func != null) {
                        output.append("// Successfully created function: " +
                            func.getName() + " size=" + func.getBody().getNumAddresses() + "\n");
                    }
                } catch (Exception e) {
                    output.append("// ERROR creating function: " + e.getMessage() + "\n");
                }
            }

            if (func == null) {
                output.append("// No function at 0x" +
                    Long.toHexString(addr).toUpperCase() + "\n\n");
                continue;
            }

            long funcEntry = func.getEntryPoint().getOffset() & 0xFFFFFFFFL;
            if (decompiled.contains(funcEntry)) {
                output.append("// 0x" + Long.toHexString(addr).toUpperCase() +
                    " already decompiled (function at 0x" +
                    Long.toHexString(funcEntry).toUpperCase() + ")\n\n");
                continue;
            }
            decompiled.add(funcEntry);

            String name = func.getName();
            long bodySize = func.getBody().getNumAddresses();
            println("Decompiling " + name + " at " + func.getEntryPoint() +
                " (size=" + bodySize + " bytes)...");

            DecompileResults results = decomp.decompileFunction(func, 180, monitor);
            if (results == null || !results.decompileCompleted()) {
                output.append("// Decompilation FAILED for " + name +
                    " at " + func.getEntryPoint() + "\n");
                if (results != null) {
                    output.append("// Error: " + results.getErrorMessage() + "\n");
                }
                output.append("\n");
                continue;
            }

            DecompiledFunction decompFunc = results.getDecompiledFunction();
            if (decompFunc == null) {
                output.append("// No decompiled output for " + name +
                    " at " + func.getEntryPoint() + "\n\n");
                continue;
            }

            output.append("// === " + name + " @ " + func.getEntryPoint() +
                " (size=" + bodySize + " bytes) ===\n");
            output.append("// Signature: " + decompFunc.getSignature() + "\n\n");
            output.append(decompFunc.getC());
            output.append("\n\n\n");
        }

        String outputPath = "C:/projects/ixus870IS/firmware-analysis/statemachine_decompiled.txt";
        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\nDecompilation output written to: " + outputPath);
        println("\n" + output.toString());
    }
}
