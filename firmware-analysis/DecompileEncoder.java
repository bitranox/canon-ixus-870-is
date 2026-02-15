// Ghidra headless script to decompile the MJPEG encoding path
// FUN_ff9e8104 is called by the pipeline frame callback with the MJPEG active flag
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

public class DecompileEncoder extends GhidraScript {

    private static final long[] ADDRS = {
        0xFF9E8104L, // FUN_ff9e8104 - MJPEG encoding check (called with +0x48 flag)
        0xFF9E5328L, // FUN_ff9e5328 - Frame processing (called with frame data and video mode)
        0xFF9E7994L, // FUN_ff9e7994 - Video mode processing
        0xFF8F8DD8L, // FUN_ff8f8dd8 - Called with param_2 in pipeline callback
        0xFF8EB574L, // FUN_ff8eb574 - Called with param_3, param_4, param_7
        0xFF8EED74L, // FUN_ff8eed74 - First call in pipeline callback
        0xFF8F6E24L, // FUN_ff8f6e24 - Second call in pipeline callback
    };

    private static final String[] NAMES = {
        "FUN_ff9e8104_MjpegEncodingCheck",
        "FUN_ff9e5328_FrameProcessing",
        "FUN_ff9e7994_VideoModeProcessing",
        "FUN_ff8f8dd8_PipelineStep2",
        "FUN_ff8eb574_PipelineStep3",
        "FUN_ff8eed74_PipelineStep0",
        "FUN_ff8f6e24_PipelineStep1",
    };

    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        StringBuilder output = new StringBuilder();
        output.append("========================================================================\n");
        output.append("MJPEG Encoding Path Decompilation\n");
        output.append("Firmware: IXUS 870 IS / SD 880 IS, version 1.01a\n");
        output.append("Purpose: Understand the MJPEG encoding trigger and frame processing\n");
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

        String outputPath = "C:/projects/ixus870IS/firmware-analysis/encoder_decompiled.txt";
        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\nDecompilation output written to: " + outputPath);
        println("\n" + output.toString());
    }
}
