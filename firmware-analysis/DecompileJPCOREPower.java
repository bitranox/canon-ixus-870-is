// Ghidra headless script to decompile JPCORE power/init functions
// Run with: analyzeHeadless <project_dir> <project_name> -process PRIMARY.BIN -noanalysis
//           -scriptPath <dir> -postScript DecompileJPCOREPower.java
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

public class DecompileJPCOREPower extends GhidraScript {

    // Target functions: address
    private static final long[] ADDRS = {
        0xFF815288L, // JPCORE clock/power enable (called by FUN_ff8eeb6c)
        0xFF8152E8L, // Additional clock init (called by FUN_ff8eeb6c)
        0xFF8EF6B4L, // JPCORE subsystem init (called by FUN_ff8eeb6c)
        0xFF8EEBC8L, // JPCORE power deinit (counterpart to FUN_ff8eeb6c)
    };

    private static final String[] NAMES = {
        "FUN_ff815288_JPCORE_clock_power_enable",
        "FUN_ff8152e8_additional_clock_init",
        "FUN_ff8ef6b4_JPCORE_subsystem_init",
        "FUN_ff8eebc8_JPCORE_power_deinit",
    };

    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        StringBuilder output = new StringBuilder();
        output.append("========================================================================\n");
        output.append("JPCORE Power/Init Function Decompilation\n");
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
        String outputPath = "C:/projects/ixus870IS/firmware-analysis/jpcore_power_decompiled.txt";

        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\nDecompilation output written to: " + outputPath);
        println("\n" + output.toString());
    }
}
