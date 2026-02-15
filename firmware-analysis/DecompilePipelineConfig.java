// Ghidra headless script to decompile ISP pipeline configuration functions
// These functions control how sensor data is routed to JPCORE for MJPEG encoding.
// Run with: analyzeHeadless <project_dir> <project_name> -process PRIMARY.BIN -noanalysis
//           -scriptPath <dir> -postScript DecompilePipelineConfig.java
//
//@category CHDK
//@author webcam-re

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import java.io.FileWriter;
import java.io.File;

public class DecompilePipelineConfig extends GhidraScript {

    private static final long[] ADDRESSES = {
        0xFFA02DDCL,  // Pipeline configuration (mode=4 EVF, mode=5 video rec)
        0xFFA03BC8L,  // Video recording pipeline setup (6 args)
        0xFFA03618L,  // EVF/LCD pipeline setup (7 args)
        0xFF8EFA6CL,  // Pipeline routing function (called with 0, 0x11)
        0xFF9E4DF8L,  // DMA/interrupt setup
        0xFF8F7110L,  // Pipeline scaler config (mode 1 or 2)
        0xFF8F70F8L,  // Pipeline scaler config (param, 1)
    };

    private static final String[] NAMES = {
        "PipelineConfig_FFA02DDC",
        "VideoRecPipelineSetup_FFA03BC8",
        "EVFPipelineSetup_FFA03618",
        "PipelineRouting_FF8EFA6C",
        "DMAInterruptSetup_FF9E4DF8",
        "PipelineScalerConfig1_FF8F7110",
        "PipelineScalerConfig2_FF8F70F8",
    };

    private static final String[] DESCRIPTIONS = {
        "Pipeline configuration function called with mode=4 (EVF) or mode=5 (video recording). KEY function that determines if ISP data is routed to JPCORE.",
        "Video recording pipeline setup (called from FUN_ff9e508c, 6 args)",
        "EVF/LCD pipeline setup (called from FUN_ff9e51d8, 7 args)",
        "Pipeline routing function (called with (0, 0x11) from FrameProcessing)",
        "DMA/interrupt setup (called from both FrameProcessing paths)",
        "Pipeline scaler config (called with mode 1 or 2)",
        "Pipeline scaler config (called with param, 1)",
    };

    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        StringBuilder output = new StringBuilder();
        output.append("========================================================================\n");
        output.append("ISP Pipeline Configuration Function Decompilation\n");
        output.append("Firmware: IXUS 870 IS / SD 880 IS, version 1.01a\n");
        output.append("Binary: PRIMARY.BIN, ARM:LE:32:v5t, base 0xFF810000\n");
        output.append("========================================================================\n\n");

        for (int i = 0; i < ADDRESSES.length; i++) {
            long addr = ADDRESSES[i];
            String name = NAMES[i];
            String desc = DESCRIPTIONS[i];

            Address address = toAddr(addr);
            println("Decompiling " + name + " at " + address + "...");

            Function func = getFunctionAt(address);
            if (func == null) {
                println("  Function not found at " + address + ", creating...");
                func = createFunction(address, name);
            }
            if (func == null) {
                output.append("// === " + name + " @ " + address + " ===\n");
                output.append("// Description: " + desc + "\n");
                output.append("// ERROR: Could not find or create function at " + address + "\n\n");
                println("  ERROR: Could not find or create function " + name + " at " + address);
                continue;
            }

            // Try to set the name (may fail if already named differently, that's ok)
            try {
                func.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED);
            } catch (Exception e) {
                println("  Note: Could not rename function: " + e.getMessage());
            }

            // Get function size info
            long funcSize = func.getBody().getNumAddresses();

            DecompileResults results = decomp.decompileFunction(func, 120, monitor);
            if (results == null || !results.decompileCompleted()) {
                output.append("// === " + name + " @ " + address + " ===\n");
                output.append("// Description: " + desc + "\n");
                output.append("// Function size: " + funcSize + " bytes\n");
                output.append("// ERROR: Decompilation failed\n");
                if (results != null) {
                    output.append("// Error message: " + results.getErrorMessage() + "\n");
                }
                output.append("\n\n");
                println("  ERROR: Decompilation failed for " + name);
                continue;
            }

            DecompiledFunction decompFunc = results.getDecompiledFunction();
            if (decompFunc == null) {
                output.append("// === " + name + " @ " + address + " ===\n");
                output.append("// Description: " + desc + "\n");
                output.append("// Function size: " + funcSize + " bytes\n");
                output.append("// ERROR: No decompiled output\n\n");
                println("  ERROR: No decompiled output for " + name);
                continue;
            }

            String sig = decompFunc.getSignature();
            String code = decompFunc.getC();

            output.append("// ========================================================================\n");
            output.append("// === " + name + " @ " + address + " ===\n");
            output.append("// Description: " + desc + "\n");
            output.append("// Function size: " + funcSize + " bytes\n");
            output.append("// Signature: " + sig + "\n");
            output.append("// ========================================================================\n\n");
            output.append(code);
            output.append("\n\n");

            println("  OK: Decompiled " + name + " (" + funcSize + " bytes)");
        }

        // Write output to file
        String outputPath = "C:\\projects\\ixus870IS\\firmware-analysis\\pipeline_config_decompiled.txt";

        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\n=== Decompilation complete ===");
        println("Output written to: " + outputPath);
    }
}
