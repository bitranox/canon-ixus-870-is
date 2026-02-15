// Ghidra headless script to decompile the JPCORE interrupt completion handler
// FUN_ff849168 and the event flag/semaphore functions used by GetContinuousMovieJpegVRAMData
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

public class DecompileJPCORE_Handler extends GhidraScript {

    private static final long[] ADDRS = {
        0xFF849168L, // FUN_ff849168 - JPCORE interrupt completion handler (called when encoding done)
        0xFF869508L, // FUN_ff869508 - "semaphore_signal" called before DMA setup
        0xFF869330L, // FUN_ff869330 - "semaphore_func" called after DMA setup (wait/poll?)
        0xFF8EBB34L, // FUN_ff8ebb34 - Called by JPCORE DMA Start with piVar1[5]
        0xFF8EF7F8L, // FUN_ff8ef7f8 - JPCORE output buffer config (writes DMA dest addr)
        0xFF8EFABCL, // FUN_ff8efabc - Register JPCORE callback
    };

    private static final String[] NAMES = {
        "FUN_ff849168_JPCORE_Interrupt_Handler",
        "FUN_ff869508_EventFlagOrSemaphore",
        "FUN_ff869330_WaitEventFlagOrSemaphore",
        "FUN_ff8ebb34_JPCOREConfig",
        "FUN_ff8ef7f8_JPCORE_SetOutputBuf",
        "FUN_ff8efabc_JPCORE_RegisterCallback",
    };

    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        StringBuilder output = new StringBuilder();
        output.append("========================================================================\n");
        output.append("JPCORE Handler & Event Flag Decompilation\n");
        output.append("Firmware: IXUS 870 IS / SD 880 IS, version 1.01a\n");
        output.append("Purpose: Find where +0x5C is checked and understand sync primitives\n");
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

            try {
                func.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED);
            } catch (Exception e) {}

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

            output.append("// === " + name + " @ " + address + " ===\n");
            output.append("// Signature: " + decompFunc.getSignature() + "\n");
            output.append(decompFunc.getC());
            output.append("\n\n\n");
        }

        String outputPath = "C:/projects/ixus870IS/firmware-analysis/jpcore_handler_decompiled.txt";
        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\nDecompilation output written to: " + outputPath);
        println("\n" + output.toString());
    }
}
