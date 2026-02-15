// Ghidra headless script to decompile GetContinuousMovieJpegVRAMData
// and related functions to understand why DMA doesn't write to VRAM buffer.
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

public class DecompileGetVRAM extends GhidraScript {

    private static final long[] ADDRS = {
        0xFFAA234CL, // GetContinuousMovieJpegVRAMData_FW - outer function
        0xFFAA2224L, // FUN_ffaa2224 - inner function (checks MJPEG active, triggers DMA)
        0xFF8C425CL, // StopContinuousVRAMData_FW - cleanup after frame capture
        0xFF8C3D38L, // FUN_ff8c3d38 - StartMjpegMaking inner
        0xFF8C3C94L, // FUN_ff8c3c94 - StopMjpegMaking inner
        0xFFAA12B0L, // LAB_ffaa12b0 - DMA completion callback (signals event flag)
        0xFF8C3C64L, // FUN_ff8c3c64 - EVF field clear (zeros +0x38/+0x3C/+0x40)
        0xFF8C3BFCL, // sub_FF8C3BFC - RecordingPipelineSetup (already decompiled but include for context)
        0xFF8F8CE8L, // FUN_ff8f8ce8 - JPCORE completion callback (called by PipelineStep3 via FUN_ff849448)
        0xFF849448L, // FUN_ff849448 - JPCORE DMA start? (called by PipelineStep3 with frame data)
    };

    private static final String[] NAMES = {
        "GetContinuousMovieJpegVRAMData_FW",
        "FUN_ffaa2224_Inner_GetContMovJpeg",
        "StopContinuousVRAMData_FW",
        "FUN_ff8c3d38_StartMjpegMaking_Inner",
        "FUN_ff8c3c94_StopMjpegMaking_Inner",
        "FUN_ffaa12b0_DMA_Completion_Callback",
        "FUN_ff8c3c64_EVF_FieldClear",
        "sub_FF8C3BFC_RecordingPipelineSetup",
        "FUN_ff8f8ce8_JPCORE_FrameComplete",
        "FUN_ff849448_JPCORE_DMA_Start",
    };

    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        StringBuilder output = new StringBuilder();
        output.append("========================================================================\n");
        output.append("GetContinuousMovieJpegVRAMData Deep Dive\n");
        output.append("Firmware: IXUS 870 IS / SD 880 IS, version 1.01a\n");
        output.append("Purpose: Understand full DMA flow and why VRAM buffer stays empty\n");
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

        String outputPath = "C:/projects/ixus870IS/firmware-analysis/getvram_decompiled.txt";
        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\nDecompilation output written to: " + outputPath);
        println("\n" + output.toString());
    }
}
