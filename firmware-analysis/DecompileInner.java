// Ghidra headless script to decompile inner MJPEG pipeline functions
// Run with: analyzeHeadless <project_dir> <project_name> -process PRIMARY.BIN -noanalysis
//           -scriptPath <dir> -postScript DecompileInner.java
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

public class DecompileInner extends GhidraScript {

    // Target functions: address
    private static final long[] ADDRS = {
        0xFFAA2224L, // FUN_ffaa2224 - inner function called by GetContinuousMovieJpegVRAMData
        0xFFAA12B0L, // LAB_ffaa12b0 - callback function passed to FUN_ffaa2224
        0xFF8C3D38L, // FUN_ff8c3d38 - inner function called by StartMjpegMaking_FW
        0xFF8C3C64L, // FUN_ff8c3c64 - called by StartEVFMovVGA to set up the pipeline
        0xFF8C3C94L, // FUN_ff8c3c94 - called by StopMjpegMaking_FW
        0xFF869508L, // FUN_ff869508 - semaphore/signaling function used by GetContinuousMovieJpegVRAMData
        0xFF869330L, // FUN_ff869330 - another semaphore function
    };

    private static final String[] NAMES = {
        "FUN_ffaa2224_GetContMovJpeg_inner",
        "LAB_ffaa12b0_callback",
        "FUN_ff8c3d38_StartMjpegMaking_inner",
        "FUN_ff8c3c64_StartEVFMovVGA_setup",
        "FUN_ff8c3c94_StopMjpegMaking_inner",
        "FUN_ff869508_semaphore_signal",
        "FUN_ff869330_semaphore_func",
    };

    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        StringBuilder output = new StringBuilder();
        output.append("========================================================================\n");
        output.append("Inner MJPEG Pipeline Function Decompilation\n");
        output.append("Firmware: IXUS 870 IS / SD 880 IS, version 1.01a\n");
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
            func.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED);

            DecompileResults results = decomp.decompileFunction(func, 60, monitor);
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
            output.append("\n\n");
        }

        // Write output to file
        String outputPath = "C:/projects/ixus870IS/firmware-analysis/mjpeg_inner_decompiled.txt";

        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\nDecompilation output written to: " + outputPath);
        println("\n" + output.toString());
    }
}
