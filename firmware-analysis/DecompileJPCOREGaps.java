// DecompileJPCOREGaps.java - Decompile critical JPCORE gap functions
// Key targets:
//   FUN_ff849448 - JPCORE_DMA_Start (WHY does it return failure?)
//   FUN_ff8f8ce8 - JPCORE_FrameComplete callback
//   FUN_ff8eeb6c - Video-mode init (called for modes 2/3 during EVF setup)
//   FUN_ff8c335c - Callback execution (calls state[+0x114])

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;

public class DecompileJPCOREGaps extends GhidraScript {

    private static final long[] ADDRS = {
        0xff849448L,  // JPCORE_DMA_Start - CRITICAL: why does it return != 1?
        0xff8f8ce8L,  // JPCORE_FrameComplete callback from PipelineStep3
        0xff8eeb6cL,  // Video-mode init (called for mode 2/3 during EVF setup)
        0xff8c335cL,  // Callback execution (calls recording callbacks at state[+0x114])
        0xff8eaa10L,  // Pipeline stage check (called 9 times in PipelineStep3 entry)
        0xff8ead78L,  // Called by PipelineStep3 with param_1, param_2, active flag
        0xff8eafc0L,  // Called by PipelineStep3 after DMA setup
        0xffa08764L,  // Called by PipelineStep3 after JPCORE_DMA_Start
        0xffa08d40L,  // Called by PipelineStep3 after ffa08764
    };

    private static final String[] DESCS = {
        "JPCORE_DMA_Start - WHY does it return failure? What are prerequisites?",
        "JPCORE_FrameComplete - callback fired when JPCORE encoding completes",
        "Video-mode init FUN_ff8eeb6c - called only for modes 2/3 during EVF setup",
        "Callback execution FUN_ff8c335c - calls recording callbacks at state[+0x114]",
        "Pipeline stage check FUN_ff8eaa10 - guards PipelineStep3 entry",
        "PipelineStep3 helper FUN_ff8ead78 - DMA address setup?",
        "PipelineStep3 helper FUN_ff8eafc0 - post-DMA config?",
        "PipelineStep3 post-DMA FUN_ffa08764",
        "PipelineStep3 post-DMA FUN_ffa08d40",
    };

    @Override
    public void run() throws Exception {
        String outputPath = "C:/projects/ixus870IS/firmware-analysis/jpcore_gaps_decompiled.txt";

        DecompInterface decomp = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decomp.setOptions(options);
        decomp.openProgram(currentProgram);

        FunctionManager funcMgr = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        AddressFactory af = currentProgram.getAddressFactory();

        PrintWriter out = new PrintWriter(new FileWriter(outputPath));

        out.println("==========================================================================");
        out.println("JPCORE Hardware Encoder - Gap Function Decompilation");
        out.println("Firmware: IXUS 870 IS / SD880 IS, version 1.01a");
        out.println("==========================================================================");
        out.println();

        for (int i = 0; i < ADDRS.length; i++) {
            long addrVal = ADDRS[i];
            String desc = DESCS[i];

            out.println("##########################################################################");
            out.println("# " + desc);
            out.printf("# Address: 0x%08x%n", addrVal);
            out.println("##########################################################################");
            out.println();

            Address addr = af.getDefaultAddressSpace().getAddress(addrVal);
            Function func = funcMgr.getFunctionAt(addr);
            if (func == null) {
                func = funcMgr.getFunctionContaining(addr);
            }

            if (func == null) {
                out.println("ERROR: No function at this address");
                out.println();
                continue;
            }

            println("Decompiling: " + func.getName() + " at " + func.getEntryPoint());

            out.println("Function: " + func.getName());
            out.println("Entry: " + func.getEntryPoint());
            out.println("Size: " + func.getBody().getNumAddresses() + " bytes");
            out.println("Signature: " + func.getPrototypeString(true, false));
            out.println();

            // Callers
            out.println("--- CALLERS ---");
            ReferenceIterator refsTo = refMgr.getReferencesTo(func.getEntryPoint());
            int cnt = 0;
            while (refsTo.hasNext()) {
                Reference ref = refsTo.next();
                Address from = ref.getFromAddress();
                Function caller = funcMgr.getFunctionContaining(from);
                String cname = (caller != null) ? caller.getName() + " (" + caller.getEntryPoint() + ")" : "(unknown)";
                out.println("  " + ref.getReferenceType() + " from " + from + " in " + cname);
                cnt++;
            }
            out.println("  Total: " + cnt);
            out.println();

            // Callees
            out.println("--- CALLEES ---");
            Set<String> callees = new LinkedHashSet<String>();
            InstructionIterator ii = currentProgram.getListing().getInstructions(func.getBody(), true);
            while (ii.hasNext()) {
                Instruction instr = ii.next();
                Reference[] refs = instr.getReferencesFrom();
                for (Reference ref : refs) {
                    if (ref.getReferenceType().isCall()) {
                        Address to = ref.getToAddress();
                        Function cf = funcMgr.getFunctionAt(to);
                        String cn = (cf != null) ? cf.getName() + " (" + cf.getEntryPoint() + ")" : "(unknown at " + to + ")";
                        callees.add("  " + instr.getAddress() + " -> " + to + " = " + cn);
                    }
                }
            }
            for (String c : callees) { out.println(c); }
            out.println("  Total: " + callees.size());
            out.println();

            // Decompile
            out.println("--- DECOMPILED CODE ---");
            DecompileResults res = decomp.decompileFunction(func, 120, monitor);
            if (res.decompileCompleted()) {
                out.println(res.getDecompiledFunction().getC());
            } else {
                out.println("DECOMPILATION FAILED: " + res.getErrorMessage());
            }
            out.println();
            out.println();
        }

        out.println("=== END ===");
        out.flush();
        out.close();
        decomp.dispose();

        println("Done. Output: " + outputPath);
    }
}
