// DecompileDispatch.java - Decompile frame dispatch, recording callback, and ISP pipeline config
// Targets:
//   1. FUN_ff9e5328 - FrameProcessing dispatcher (checks state[+0xD4] for video vs EVF)
//   2. FUN_ff8c335c - Recording callback dispatch (calls state[+0x114] and state[+0x118])
//   3. FUN_ffa02ddc - PipelineConfig (ISP routing, mode=5 video / mode=4 EVF)
//
// Run with:
//   analyzeHeadless <project_dir> ixus870_101a -process PRIMARY.BIN -noanalysis
//                   -scriptPath <dir> -postScript DecompileDispatch.java

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
import ghidra.program.model.mem.Memory;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;

public class DecompileDispatch extends GhidraScript {

    private static final long[] ADDRS = {
        0xff9e5328L,  // FrameProcessing dispatcher - checks state[+0xD4]
        0xff8c335cL,  // Recording callback dispatch - calls state[+0x114]/[+0x118]
        0xffa02ddcL,  // PipelineConfig - ISP routing (mode=5 video, mode=4 EVF)
    };

    private static final String[] DESCS = {
        "FUN_ff9e5328 - FrameProcessing dispatcher (state[+0xD4] video vs EVF)",
        "FUN_ff8c335c - Recording callback dispatch (state[+0x114] and state[+0x118])",
        "PipelineConfig_FFA02DDC - ISP routing config (mode=5 video, mode=4 EVF)",
    };

    @Override
    public void run() throws Exception {
        String outputPath = "C:/projects/ixus870IS/firmware-analysis/dispatch_decompiled.txt";

        DecompInterface decomp = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decomp.setOptions(options);
        decomp.openProgram(currentProgram);

        FunctionManager funcMgr = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        AddressFactory af = currentProgram.getAddressFactory();
        Memory mem = currentProgram.getMemory();

        PrintWriter out = new PrintWriter(new FileWriter(outputPath));

        out.println("==========================================================================");
        out.println("Dispatch & Pipeline Config Decompilation");
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
            if (func == null) func = funcMgr.getFunctionContaining(addr);

            if (func == null) {
                out.println("ERROR: No function at this address");
                out.println();
                continue;
            }

            println("Decompiling: " + func.getName() + " at " + func.getEntryPoint());

            out.println("Function: " + func.getName());
            out.println("Entry: " + func.getEntryPoint());
            out.println("Size: " + func.getBody().getNumAddresses() + " bytes");
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
            out.println();
            DecompileResults res = decomp.decompileFunction(func, 120, monitor);
            if (res.decompileCompleted()) {
                out.println(res.getDecompiledFunction().getC());
            } else {
                out.println("DECOMPILATION FAILED: " + res.getErrorMessage());
            }
            out.println();

            // ROM data references (literal pool values)
            out.println("--- ROM DATA REFERENCES ---");
            InstructionIterator ii2 = currentProgram.getListing().getInstructions(func.getBody(), true);
            int dataRefCount = 0;
            while (ii2.hasNext()) {
                Instruction instr = ii2.next();
                for (int op = 0; op < instr.getNumOperands(); op++) {
                    Reference[] opRefs = instr.getOperandReferences(op);
                    for (Reference ref : opRefs) {
                        if (ref.getReferenceType().isData()) {
                            Address refAddr = ref.getToAddress();
                            try {
                                long val = mem.getInt(refAddr) & 0xFFFFFFFFL;
                                out.printf("  %s: [%s] = 0x%08X (%d)%n",
                                    instr.getAddress(), refAddr, val, val);
                                dataRefCount++;
                            } catch (Exception e) {
                                out.printf("  %s: [%s] = (unreadable)%n",
                                    instr.getAddress(), refAddr);
                                dataRefCount++;
                            }
                        }
                    }
                }
            }
            out.println("  Total: " + dataRefCount);
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
