import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import java.io.*;

public class DecompilePipelineCB extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outPath = "C:/projects/ixus870IS/firmware-analysis/pipeline_cb_decompiled.txt";
        PrintWriter out = new PrintWriter(new FileWriter(outPath));

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        String[][] targets = {
            {"ff8c1fe4", "FUN_ff8c1fe4_PipelineFrameCallback"},
            {"ff8c4208", "FUN_ff8c4208_DMA_trigger"},
            {"ff8c4288", "FUN_ff8c4288_MjpegActiveCheck"}
        };

        out.println("==========================================================================");
        out.println("Pipeline Frame Callback + DMA Decompilation");
        out.println("==========================================================================");

        for (String[] t : targets) {
            Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseLong(t[0], 16));
            Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
            if (func == null) func = getFunctionContaining(addr);

            out.println();
            out.println("##########################################################################");
            out.println("# " + t[1]);
            out.println("# Address: 0x" + t[0]);
            out.println("##########################################################################");
            out.println();

            if (func == null) {
                out.println("ERROR: No function at 0x" + t[0]);
                continue;
            }

            out.println("Function: " + func.getName());
            out.println("Entry: " + func.getEntryPoint());
            out.println("Size: " + func.getBody().getNumAddresses() + " bytes");

            // Callers
            out.println();
            out.println("--- CALLERS ---");
            var refs = getReferencesTo(func.getEntryPoint());
            int cnt = 0;
            for (var ref : refs) {
                Function caller = getFunctionContaining(ref.getFromAddress());
                String cn = (caller != null) ? caller.getName() + " (" + caller.getEntryPoint() + ")" : "unknown";
                out.println("  " + ref.getReferenceType() + " from " + ref.getFromAddress() + " in " + cn);
                cnt++;
            }
            out.println("  Total: " + cnt);

            // Callees
            out.println();
            out.println("--- CALLEES ---");
            var instructions = currentProgram.getListing().getInstructions(func.getBody(), true);
            cnt = 0;
            while (instructions.hasNext()) {
                var instr = instructions.next();
                if (instr.getFlowType().isCall()) {
                    for (var target : instr.getFlows()) {
                        Function callee = getFunctionContaining(target);
                        String cn = (callee != null) ? callee.getName() + " (" + callee.getEntryPoint() + ")" : "unknown";
                        out.println("  " + instr.getAddress() + " -> " + target + " = " + cn);
                        cnt++;
                    }
                }
            }
            out.println("  Total: " + cnt);

            // Decompile
            out.println();
            out.println("--- DECOMPILED CODE ---");
            out.println();
            DecompileResults result = decomp.decompileFunction(func, 120, monitor);
            if (result.getDecompiledFunction() != null) {
                out.println(result.getDecompiledFunction().getC());
            } else {
                out.println("ERROR: Decompilation failed: " + result.getErrorMessage());
            }

            // ROM data references
            out.println("--- ROM DATA REFERENCES ---");
            var instrs2 = currentProgram.getListing().getInstructions(func.getBody(), true);
            while (instrs2.hasNext()) {
                var instr = instrs2.next();
                for (int i = 0; i < instr.getNumOperands(); i++) {
                    var opRefs = instr.getOperandReferences(i);
                    for (var ref : opRefs) {
                        if (ref.getReferenceType().isData()) {
                            Address refAddr = ref.getToAddress();
                            try {
                                long val = currentProgram.getMemory().getInt(refAddr);
                                out.printf("  %s: [%s] = 0x%08X (%d)%n",
                                    instr.getAddress(), refAddr, val & 0xFFFFFFFFL, val);
                            } catch (Exception e) {
                                out.printf("  %s: [%s] = (unreadable)%n", instr.getAddress(), refAddr);
                            }
                        }
                    }
                }
            }
        }

        decomp.dispose();
        out.close();
        println("Done. Output: " + outPath);
    }
}
