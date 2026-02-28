// Ghidra script: Decompile task_MovWrite and related functions
// Run headlessly:
//   analyzeHeadless C:\projects\ixus870IS\firmware-analysis\ghidra_project ixus870_101a
//     -process -noanalysis -scriptPath C:\projects\ixus870IS\firmware-analysis
//     -postScript DecompileMovWrite.java
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.address.Address;

import java.io.*;
import java.util.*;

public class DecompileMovWrite extends GhidraScript {

    private DecompInterface decomp;
    private Set<Long> visited = new HashSet<>();
    private StringBuilder output = new StringBuilder();

    // Functions we already know well — skip recursing into them
    private static final Set<Long> SKIP_ADDRS = new HashSet<>(Arrays.asList(
        0xFF9300B4L, 0xFF92FE8CL, 0xFF8EDBE0L, 0xFF8EDC88L,
        0xFF85D98CL, 0xFF85D3BCL, 0xFF8C3BFCL
    ));

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        long[] targets = {
            0xFF92F1ECL,  // task_MovWrite
            0xFF92FCFCL,  // FUN_ff92fcfc (flush trigger from sub_FF9300B4)
            0xFF92F428L,  // task_MovWrite setup (creates queue, task)
        };

        for (long t : targets) {
            decompileAt(t, 0, 2);
        }

        String outDir = getSourceFile().getParentFile().getAbsolutePath();
        String outPath = outDir + File.separator + "task_movwrite_decompiled.txt";
        PrintWriter pw = new PrintWriter(new FileWriter(outPath));
        pw.print(output.toString());
        pw.close();
        println("Wrote " + output.length() + " chars to " + outPath);
    }

    private void decompileAt(long addr, int depth, int maxDepth) {
        if (depth > maxDepth) return;
        if (visited.contains(addr)) return;
        visited.add(addr);

        Address address = toAddr(addr);
        FunctionManager fm = currentProgram.getFunctionManager();
        Function func = fm.getFunctionAt(address);
        if (func == null) {
            output.append(String.format("\n// No function found at 0x%08X\n", addr));
            return;
        }

        DecompileResults results = decomp.decompileFunction(func, 30, monitor);
        if (results == null || !results.decompileCompleted()) {
            output.append(String.format("\n// Failed to decompile 0x%08X\n", addr));
            return;
        }

        String cCode = results.getDecompiledFunction().getC();

        output.append("\n\n");
        output.append("========================================================================\n");
        output.append(String.format("Function: %s @ 0x%08X (size=%d bytes)\n",
                      func.getName(), addr, func.getBody().getNumAddresses()));
        output.append("========================================================================\n");

        // Show callers
        Set<Function> callers = func.getCallingFunctions(monitor);
        if (!callers.isEmpty()) {
            output.append("// Called from:\n");
            for (Function caller : callers) {
                output.append(String.format("//   0x%s (%s)\n",
                    caller.getEntryPoint(), caller.getName()));
            }
        }

        output.append("\n\n");
        output.append(cCode);

        // Recurse into callees
        if (depth < maxDepth) {
            Set<Function> callees = func.getCalledFunctions(monitor);
            for (Function callee : callees) {
                long calleeAddr = callee.getEntryPoint().getOffset();
                if (calleeAddr < 0xFF800000L) continue;
                if (SKIP_ADDRS.contains(calleeAddr)) continue;
                decompileAt(calleeAddr, depth + 1, maxDepth);
            }
        }
    }
}
