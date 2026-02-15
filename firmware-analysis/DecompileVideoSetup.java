// DecompileVideoPath.java - Decompile video FrameProcessing to understand ISP routing
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

public class DecompileVideoSetup extends GhidraScript {

    private static final long[] ADDRS = {
        0xff9e508cL,  // Video FrameProcessing (mode 2 path, calls VideoRecPipelineSetup)
        0xff9e51d8L,  // EVF FrameProcessing (mode 1 path, calls EVFPipelineSetup)
        0xff9e6ce8L,  // Caller of FUN_ff8c335c (callback dispatcher)
        0xff85d28cL,  // RecordingCallback2 (registered at state[+0x118])
        0xff85d370L,  // RecordingCallback1 (registered at state[+0x114])
    };

    private static final String[] DESCS = {
        "FUN_ff9e508c - Video FrameProcessing (mode 2, calls VideoRecPipelineSetup with mode=5?)",
        "FUN_ff9e51d8 - EVF FrameProcessing (mode 1, calls EVFPipelineSetup with mode=4)",
        "FUN_ff9e6ce8 - Frame delivery/callback dispatch (calls FUN_ff8c335c)",
        "FUN_ff85d28c - RecordingCallback2 (movie_rec.c state[+0x118])",
        "FUN_ff85d370 - RecordingCallback1 (movie_rec.c state[+0x114])",
    };

    @Override
    public void run() throws Exception {
        String outputPath = "C:/projects/ixus870IS/firmware-analysis/video_path_decompiled.txt";

        DecompInterface decomp = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decomp.setOptions(options);
        decomp.openProgram(currentProgram);

        FunctionManager funcMgr = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        AddressFactory af = currentProgram.getAddressFactory();

        PrintWriter out = new PrintWriter(new FileWriter(outputPath));

        out.println("==========================================================================");
        out.println("Video Path Decompilation - ISP to JPCORE routing");
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
