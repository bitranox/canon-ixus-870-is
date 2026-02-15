// Ghidra headless script - Phase 2: Decompile deeper ISP/JPCORE pipeline functions
// discovered from Phase 1 analysis.
//
//@category CHDK
//@author webcam-re

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import java.io.FileWriter;

public class DecompileISPRouting2 extends GhidraScript {

    private static final long[] ADDRS = {
        0xFFA03BC8L, // VideoRecPipelineSetup - called from VideoRecPath with (buf, 2, local_60, local_64, &local_3c, auStack_5c)
        0xFFA99DE0L, // FUN_ffa99de0 - ISP sensor config, called from FUN_ff9e4ef0
        0xFFA99AD8L, // FUN_ffa99ad8 - ISP color matrix?, called from FUN_ff9e4ef0
        0xFFA99FB8L, // FUN_ffa99fb8 - ISP config array, called from FUN_ff9e4ef0
        0xFFA99F6CL, // FUN_ffa99f6c - ISP config array2, called from FUN_ff9e4ef0
        0xFF9E8434L, // FUN_ff9e8434 - resolution/mode query, called from FUN_ff9e4ef0
        0xFF822B18L, // FUN_ff822b18 - register block write (memcpy to HW regs), called from DMAInterruptSetup
        0xFF822AF4L, // FUN_ff822af4 - register read-modify-write, called from DMAInterruptSetup
        0xFF826F0CL, // FUN_ff826f0c - interrupt registration, called from JPCORE_RegisterCallback
        0xFF9E81A0L, // FUN_ff9e81a0 - JPCORE disable (counterpart to ff9e8190 enable)
    };

    private static final String[] NAMES = {
        "VideoRecPipelineSetup_FFA03BC8",
        "FUN_ffa99de0_ISPSensorConfig",
        "FUN_ffa99ad8_ISPColorMatrix",
        "FUN_ffa99fb8_ISPConfigArray",
        "FUN_ffa99f6c_ISPConfigArray2",
        "FUN_ff9e8434_ResolutionQuery",
        "FUN_ff822b18_RegBlockWrite",
        "FUN_ff822af4_RegRMW",
        "FUN_ff826f0c_InterruptReg",
        "FUN_ff9e81a0_JPCORE_disable",
    };

    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        StringBuilder output = new StringBuilder();
        output.append("========================================================================\n");
        output.append("ISP-to-JPCORE Routing - Phase 2 Deep Dive\n");
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
                output.append("// ERROR: Could not find or create function " + name + " at " + address + "\n\n");
                continue;
            }

            try {
                func.setName(name, SourceType.USER_DEFINED);
            } catch (Exception e) {
                // Name may already be set
            }

            DecompileResults results = decomp.decompileFunction(func, 120, monitor);
            if (results == null || !results.decompileCompleted()) {
                output.append("// ERROR: Decompilation failed for " + name + " at " + address + "\n");
                if (results != null) {
                    output.append("// Error: " + results.getErrorMessage() + "\n");
                }
                output.append("\n");
                continue;
            }

            DecompiledFunction decompFunc = results.getDecompiledFunction();
            if (decompFunc == null) {
                output.append("// ERROR: No decompiled output for " + name + " at " + address + "\n\n");
                continue;
            }

            output.append("// ======================================================================\n");
            output.append("// === " + name + " @ " + address + " ===\n");
            output.append("// ======================================================================\n");
            output.append("// Signature: " + decompFunc.getSignature() + "\n");
            output.append(decompFunc.getC());
            output.append("\n\n");
        }

        String outputPath = "C:/projects/ixus870IS/firmware-analysis/isp_routing_phase2.txt";
        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\nPhase 2 output written to: " + outputPath);
        println("\n" + output.toString());

        decomp.dispose();
    }
}
