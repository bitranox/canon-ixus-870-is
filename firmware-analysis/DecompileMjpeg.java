// Ghidra headless script to decompile hardware MJPEG functions
// Run with: analyzeHeadless <project_dir> <project_name> -process PRIMARY.BIN -noanalysis
//           -scriptPath <dir> -postScript DecompileMjpeg.java
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

public class DecompileMjpeg extends GhidraScript {

    // Target functions: address, name
    private static final long[][] TARGETS = {
        {0xFF9E8DD8L, 0}, // StartMjpegMaking_FW
        {0xFF9E8DF8L, 0}, // StopMjpegMaking_FW
        {0xFFAA234CL, 0}, // GetContinuousMovieJpegVRAMData_FW
        {0xFF8C4178L, 0}, // GetMovieJpegVRAMHPixelsSize_FW
        {0xFF8C4184L, 0}, // GetMovieJpegVRAMVPixelsSize_FW
        {0xFF8C425CL, 0}, // StopContinuousVRAMData_FW
        {0xFF9E8944L, 0}, // StartEVFMovVGA_FW
        {0xFF9E8A24L, 0}, // StartEVFMovQVGA60_FW
        {0xFF9E8C58L, 0}, // StartEVFMovXGA_FW
        {0xFF9E8D10L, 0}, // StartEVFMovHD_FW
        {0xFF9E8DC8L, 0}, // StopEVF_FW
    };

    private static final String[] NAMES = {
        "StartMjpegMaking_FW",
        "StopMjpegMaking_FW",
        "GetContinuousMovieJpegVRAMData_FW",
        "GetMovieJpegVRAMHPixelsSize_FW",
        "GetMovieJpegVRAMVPixelsSize_FW",
        "StopContinuousVRAMData_FW",
        "StartEVFMovVGA_FW",
        "StartEVFMovQVGA60_FW",
        "StartEVFMovXGA_FW",
        "StartEVFMovHD_FW",
        "StopEVF_FW",
    };

    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        StringBuilder output = new StringBuilder();
        output.append("========================================================================\n");
        output.append("Hardware MJPEG Function Decompilation\n");
        output.append("Firmware: IXUS 870 IS / SD 880 IS, version 1.01a\n");
        output.append("========================================================================\n\n");

        for (int i = 0; i < TARGETS.length; i++) {
            long addr = TARGETS[i][0];
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
        String scriptDir = getSourceFile().getParentFile().getAbsolutePath();
        String outputPath = scriptDir + File.separator + "mjpeg_decompiled.txt";

        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\nDecompilation output written to: " + outputPath);
        println("\n" + output.toString());
    }
}
