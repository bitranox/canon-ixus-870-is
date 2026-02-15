// Ghidra headless script to decompile ISP-to-JPCORE routing functions
// Goal: Understand how the ISP source register 0xC0F110C4 gets configured
//       during movie recording so that JPCORE receives input data.
//
// Run with: analyzeHeadless <project_dir> <project_name> -process PRIMARY.BIN -noanalysis
//           -scriptPath <dir> -postScript DecompileISPRouting.java
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
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.SourceType;
import java.io.FileWriter;
import java.io.File;

public class DecompileISPRouting extends GhidraScript {

    // Primary targets: ISP routing / JPCORE pipeline functions
    private static final long[] ADDRS = {
        0xFF9E8190L, // FUN_ff9e8190 - "Enable JPCORE pipeline" called by StartMjpegMaking
        0xFF8C3BFCL, // sub_FF8C3BFC - Recording pipeline setup (crashes without movie_record_task)
        0xFF9E508CL, // FUN_ff9e508c - Video recording path from FrameProcessing when state[+0xD4]=2
        0xFFA02DDCL, // FUN_ffa02ddc - Pipeline resizer config, mode=5 for recording
        0xFF8C335CL, // FUN_ff8c335c - Frame processing callback dispatch at state[+0x114]
    };

    private static final String[] NAMES = {
        "FUN_ff9e8190_JPCORE_enable",
        "sub_FF8C3BFC_RecPipelineSetup",
        "FUN_ff9e508c_VideoRecPath",
        "FUN_ffa02ddc_PipelineResizer",
        "FUN_ff8c335c_FrameDispatch",
    };

    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        StringBuilder output = new StringBuilder();
        output.append("========================================================================\n");
        output.append("ISP-to-JPCORE Routing Function Decompilation\n");
        output.append("Firmware: IXUS 870 IS / SD 880 IS, version 1.01a\n");
        output.append("Focus: ISP/JPCORE I/O registers 0xC0F00000 - 0xC0F1FFFF\n");
        output.append("========================================================================\n\n");

        // Decompile each primary target
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

            func.setName(name, SourceType.USER_DEFINED);

            DecompileResults results = decomp.decompileFunction(func, 120, monitor);
            if (results == null || !results.decompileCompleted()) {
                output.append("// ERROR: Decompilation failed for " + name + " at " + address + "\n");
                if (results != null) {
                    output.append("// Error message: " + results.getErrorMessage() + "\n");
                }
                output.append("\n");
                continue;
            }

            DecompiledFunction decompFunc = results.getDecompiledFunction();
            if (decompFunc == null) {
                output.append("// ERROR: No decompiled output for " + name + " at " + address + "\n\n");
                continue;
            }

            String sig = decompFunc.getSignature();
            String code = decompFunc.getC();

            output.append("// ======================================================================\n");
            output.append("// === " + name + " @ " + address + " ===\n");
            output.append("// ======================================================================\n");
            output.append("// Signature: " + sig + "\n");
            output.append(code);
            output.append("\n\n");

            // Scan for hardware register references in the function body
            scanHardwareRegs(func, name, output);
        }

        // Now find and decompile any sub-functions called by our targets that
        // reference ISP/JPCORE registers (0xC0F0xxxx - 0xC0F1xxxx)
        output.append("\n========================================================================\n");
        output.append("SUB-FUNCTION DISCOVERY: Functions called by targets that reference\n");
        output.append("ISP/JPCORE hardware registers (0xC0F00000 - 0xC0F1FFFF)\n");
        output.append("========================================================================\n\n");

        // Collect called functions from all targets
        java.util.Set<Long> alreadyDecompiled = new java.util.HashSet<>();
        for (long a : ADDRS) alreadyDecompiled.add(a);

        java.util.LinkedHashMap<Long, String> subFuncs = new java.util.LinkedHashMap<>();

        for (int i = 0; i < ADDRS.length; i++) {
            Address address = toAddr(ADDRS[i]);
            Function func = getFunctionAt(address);
            if (func == null) continue;

            // Get all called functions
            java.util.Set<Function> called = func.getCalledFunctions(monitor);
            for (Function callee : called) {
                long calleeAddr = callee.getEntryPoint().getOffset();
                if (!alreadyDecompiled.contains(calleeAddr) && !subFuncs.containsKey(calleeAddr)) {
                    // Check if this function references ISP/JPCORE register space
                    if (referencesHardwareRegisters(callee)) {
                        subFuncs.put(calleeAddr, NAMES[i] + " -> " + callee.getName());
                    }
                }
            }
        }

        if (subFuncs.isEmpty()) {
            output.append("// No sub-functions found with direct ISP/JPCORE register references.\n");
            output.append("// Trying deeper scan: decompiling ALL called functions from targets...\n\n");

            // Decompile all called functions from targets to catch indirect references
            for (int i = 0; i < ADDRS.length; i++) {
                Address address = toAddr(ADDRS[i]);
                Function func = getFunctionAt(address);
                if (func == null) continue;

                java.util.Set<Function> called = func.getCalledFunctions(monitor);
                for (Function callee : called) {
                    long calleeAddr = callee.getEntryPoint().getOffset();
                    if (!alreadyDecompiled.contains(calleeAddr)) {
                        subFuncs.put(calleeAddr, NAMES[i] + " -> " + callee.getName());
                        alreadyDecompiled.add(calleeAddr);
                    }
                }
            }
        }

        // Decompile discovered sub-functions
        int subCount = 0;
        for (java.util.Map.Entry<Long, String> entry : subFuncs.entrySet()) {
            long addr = entry.getKey();
            String context = entry.getValue();

            Address address = toAddr(addr);
            Function func = getFunctionAt(address);
            if (func == null) continue;

            DecompileResults results = decomp.decompileFunction(func, 120, monitor);
            if (results == null || !results.decompileCompleted()) continue;

            DecompiledFunction decompFunc = results.getDecompiledFunction();
            if (decompFunc == null) continue;

            String code = decompFunc.getC();

            // Only include if it references hardware registers or is relatively short
            boolean hasHwReg = code.contains("0xc0f") || code.contains("0xC0F") ||
                               code.contains("0xc0e") || code.contains("0xC0E");
            boolean isShort = code.length() < 3000;

            if (hasHwReg || isShort) {
                output.append("// === " + func.getName() + " @ " + address + " ===\n");
                output.append("// Called from: " + context + "\n");
                output.append("// Signature: " + decompFunc.getSignature() + "\n");
                if (hasHwReg) {
                    output.append("// *** CONTAINS HARDWARE REGISTER REFERENCES ***\n");
                }
                output.append(code);
                output.append("\n\n");
                subCount++;
            }
        }

        output.append("// Total sub-functions decompiled: " + subCount + "\n");

        // Write output to file
        String outputPath = "C:/projects/ixus870IS/firmware-analysis/isp_routing_decompiled.txt";

        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\nDecompilation output written to: " + outputPath);
        println("\n" + output.toString());

        decomp.dispose();
    }

    /**
     * Scan a function's instruction bytes for references to hardware register space.
     * Reports any constants in 0xC0E00000-0xC0FFFFFF range found in the function.
     */
    private void scanHardwareRegs(Function func, String funcName, StringBuilder output) {
        AddressSetView body = func.getBody();
        InstructionIterator iter = currentProgram.getListing().getInstructions(body, true);

        java.util.LinkedHashSet<String> hwRegs = new java.util.LinkedHashSet<>();

        while (iter.hasNext()) {
            Instruction instr = iter.next();
            String repr = instr.toString();
            int numOps = instr.getNumOperands();
            for (int op = 0; op < numOps; op++) {
                Object[] opObjs = instr.getOpObjects(op);
                for (Object obj : opObjs) {
                    if (obj instanceof ghidra.program.model.scalar.Scalar) {
                        long val = ((ghidra.program.model.scalar.Scalar) obj).getUnsignedValue();
                        if (val >= 0xC0E00000L && val <= 0xC0FFFFFFL) {
                            hwRegs.add(String.format("0x%08X", val));
                        }
                    }
                    if (obj instanceof Address) {
                        long val = ((Address) obj).getOffset();
                        if (val >= 0xC0E00000L && val <= 0xC0FFFFFFL) {
                            hwRegs.add(String.format("0x%08X", val));
                        }
                    }
                }
            }
        }

        if (!hwRegs.isEmpty()) {
            output.append("// Hardware register references in " + funcName + ":\n");
            for (String reg : hwRegs) {
                output.append("//   " + reg + "\n");
            }
            output.append("\n");
        }
    }

    /**
     * Check if a function body contains references to ISP/JPCORE hardware register space.
     */
    private boolean referencesHardwareRegisters(Function func) {
        AddressSetView body = func.getBody();
        InstructionIterator iter = currentProgram.getListing().getInstructions(body, true);

        while (iter.hasNext()) {
            Instruction instr = iter.next();
            int numOps = instr.getNumOperands();
            for (int op = 0; op < numOps; op++) {
                Object[] opObjs = instr.getOpObjects(op);
                for (Object obj : opObjs) {
                    if (obj instanceof ghidra.program.model.scalar.Scalar) {
                        long val = ((ghidra.program.model.scalar.Scalar) obj).getUnsignedValue();
                        if (val >= 0xC0F00000L && val <= 0xC0F1FFFFL) {
                            return true;
                        }
                    }
                    if (obj instanceof Address) {
                        long val = ((Address) obj).getOffset();
                        if (val >= 0xC0F00000L && val <= 0xC0F1FFFFL) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }
}
