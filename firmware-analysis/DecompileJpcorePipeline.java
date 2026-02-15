// Ghidra headless script to decompile the JPCORE pipeline encoding functions.
//
// Critical missing functions:
//   FUN_ff9e8104 — MjpegEncodingCheck: called by pipeline callback, checks MJPEG active
//   FUN_ff8f8dd8 — PipelineStep2: calls JPCORE_DMA_Start (at 0xFF8F8E1C)
//   FUN_ff8eb574 — PipelineStep3: triggers JPCORE encoding
//   FUN_ff9e5328 — FrameProcessing: post-encode frame handling
//   FUN_ff9e7994 — VideoModeProcessing: video mode output
//   FUN_ff8ef7f8 — JPCORE output program (called by FrameComplete)
//   FUN_ff8eed74 — PipelineStep0: resize/color conversion
//   FUN_ff8f6e24 — PipelineStep1
//   FUN_ff836e74 — Pipeline frame callback registration
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
import ghidra.program.model.symbol.SourceType;
import java.io.FileWriter;
import java.util.LinkedHashSet;
import java.util.Set;

public class DecompileJpcorePipeline extends GhidraScript {

    private static final long[][] TARGETS = {
        // {address, forceCreate}
        {0xFF9E8104L, 0}, // MjpegEncodingCheck
        {0xFF8F8DD8L, 0}, // PipelineStep2 (contains BL to JPCORE_DMA_Start at 0xFF8F8E1C)
        {0xFF8EB574L, 0}, // PipelineStep3
        {0xFF9E5328L, 0}, // FrameProcessing
        {0xFF9E7994L, 0}, // VideoModeProcessing
        {0xFF8EF7F8L, 0}, // JPCORE output program function
        {0xFF8EF838L, 0}, // JPCORE setup function (called by JPCORE_DMA_Start)
        {0xFF8EF930L, 0}, // Another JPCORE config
        {0xFF8EFA80L, 0}, // JPCORE quality config
        {0xFF8EFABCL, 0}, // JPCORE callback registration
        {0xFF8EFAF8L, 0}, // JPCORE start
        {0xFF8EFA44L, 0}, // JPCORE parameter
        {0xFF8EBB34L, 0}, // Called by JPCORE_DMA_Start with piVar1[5]
        {0xFF849168L, 0}, // JPCORE completion callback (registered by JPCORE_DMA_Start)
    };

    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        FunctionManager funcMgr = currentProgram.getFunctionManager();

        StringBuilder output = new StringBuilder();
        output.append("========================================================================\n");
        output.append("JPCORE Pipeline Functions\n");
        output.append("Firmware: IXUS 870 IS / SD 880 IS, version 1.01a\n");
        output.append("Purpose: Understand JPCORE encoding trigger and output path\n");
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
                try {
                    func = createFunction(funcAddr, "FUN_" +
                        Long.toHexString(addr).toLowerCase());
                    if (func != null) {
                        output.append("// Created: " + func.getName() +
                            " size=" + func.getBody().getNumAddresses() + "\n");
                    }
                } catch (Exception e) {
                    output.append("// ERROR: " + e.getMessage() + "\n");
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
                    " in already-decompiled " + func.getName() + " at 0x" +
                    Long.toHexString(funcEntry).toUpperCase() + "\n\n");
                continue;
            }
            decompiled.add(funcEntry);

            String name = func.getName();
            long bodySize = func.getBody().getNumAddresses();
            println("Decompiling " + name + " at " + func.getEntryPoint() +
                " (size=" + bodySize + ")...");

            DecompileResults results = decomp.decompileFunction(func, 180, monitor);
            if (results == null || !results.decompileCompleted()) {
                output.append("// FAILED: " + name + " at " + func.getEntryPoint() + "\n");
                if (results != null) {
                    output.append("// Error: " + results.getErrorMessage() + "\n");
                }
                output.append("\n");
                continue;
            }

            DecompiledFunction decompFunc = results.getDecompiledFunction();
            if (decompFunc == null) {
                output.append("// No output: " + name + "\n\n");
                continue;
            }

            output.append("// === " + name + " @ " + func.getEntryPoint() +
                " (size=" + bodySize + ") ===\n");
            output.append("// Signature: " + decompFunc.getSignature() + "\n\n");
            output.append(decompFunc.getC());
            output.append("\n\n\n");
        }

        String outputPath = "C:/projects/ixus870IS/firmware-analysis/jpcore_pipeline_decompiled.txt";
        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\nOutput: " + outputPath);
    }
}
