// Ghidra headless script to decompile critical DMA/pipeline functions
// that haven't been analyzed yet but are needed to understand why
// the JPCORE DMA doesn't write to the VRAM buffer.
//
// Run with: analyzeHeadless <project_dir> <project_name> -process PRIMARY.BIN -noanalysis
//           -scriptPath <dir> -postScript DecompileDMA.java
//
//@category CHDK
//@author webcam-re

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.FileWriter;
import java.io.File;

public class DecompileDMA extends GhidraScript {

    // Target functions: address
    private static final long[] ADDRS = {
        0xFF8C4208L, // FUN_ff8c4208 - DMA trigger function (called by FUN_ffaa2224)
        0xFF8C4288L, // FUN_ff8c4288 - MJPEG active check (returns 1 if active)
        0xFF9E8190L, // FUN_ff9e8190 - JPCORE enable (called by StartMjpegMaking_inner)
        0xFF9E81A0L, // FUN_ff9e81a0 - JPCORE disable (called by StopMjpegMaking_inner)
        0xFF8C3BFCL, // sub_FF8C3BFC - Recording pipeline setup (called by movie_record_task)
        0xFF92FE8CL, // sub_FF92FE8C - Movie frame getter (4 output pointers)
        0xFF8C4C60L, // FUN_ff8c4c60 - Called at start of EVF setup functions
        0xFF8C2ED8L, // FUN_ff8c2ed8 - Called by FUN_ff8c3c64 (EVF pipeline setup)
        0xFF812538L, // FUN_ff812538 - Event flag set (underlying OS call)
        0xFF812588L, // FUN_ff812588 - Event flag wait (underlying OS call)
        0xFF8EDBE0L, // sub_FF8EDBE0 - Called by movie_rec sub_FF85D98C_my for encoding
        0xFF8EDC88L, // sub_FF8EDC88 - Called after frame encoding in movie_rec
        0xFF8EDCC4L, // sub_FF8EDCC4 - Called after frame encoding in movie_rec
    };

    private static final String[] NAMES = {
        "FUN_ff8c4208_DMA_trigger",
        "FUN_ff8c4288_MjpegActiveCheck",
        "FUN_ff9e8190_JPCORE_enable",
        "FUN_ff9e81a0_JPCORE_disable",
        "sub_FF8C3BFC_RecordingPipelineSetup",
        "sub_FF92FE8C_MovieFrameGetter",
        "FUN_ff8c4c60_EVF_init",
        "FUN_ff8c2ed8_EVF_pipeline_setup",
        "FUN_ff812538_EventFlagSet",
        "FUN_ff812588_EventFlagWait",
        "sub_FF8EDBE0_EncodeFrame",
        "sub_FF8EDC88_PostEncode1",
        "sub_FF8EDCC4_PostEncode2",
    };

    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        StringBuilder output = new StringBuilder();
        output.append("========================================================================\n");
        output.append("DMA / Pipeline Function Decompilation\n");
        output.append("Firmware: IXUS 870 IS / SD 880 IS, version 1.01a\n");
        output.append("Purpose: Understand why JPCORE DMA does not write to VRAM buffer\n");
        output.append("========================================================================\n\n");

        for (int i = 0; i < ADDRS.length; i++) {
            long addr = ADDRS[i];
            String name = NAMES[i];

            Address address = toAddr(addr);
            println("Decompiling " + name + " at " + address + "...");

            Function func = getFunctionAt(address);
            if (func == null) {
                func = createFunction(address, name);
            }
            if (func == null) {
                output.append("// Could not find or create function " + name + " at " + address + "\n\n");
                continue;
            }

            // Label the function
            try {
                func.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED);
            } catch (Exception e) {
                // Name might already be set, ignore
            }

            DecompileResults results = decomp.decompileFunction(func, 120, monitor);
            if (results == null || !results.decompileCompleted()) {
                output.append("// Decompilation failed for " + name + " at " + address + "\n\n");
                continue;
            }

            DecompiledFunction decompFunc = results.getDecompiledFunction();
            if (decompFunc == null) {
                output.append("// No decompiled output for " + name + " at " + address + "\n\n");
                continue;
            }

            String sig = decompFunc.getSignature();
            String code = decompFunc.getC();

            output.append("// === " + name + " @ " + address + " ===\n");
            output.append("// Signature: " + sig + "\n");
            output.append(code);
            output.append("\n\n\n");
        }

        // Write output to file
        String outputPath = "C:/projects/ixus870IS/firmware-analysis/dma_pipeline_decompiled.txt";

        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\nDecompilation output written to: " + outputPath);
        println("\n" + output.toString());
    }
}
