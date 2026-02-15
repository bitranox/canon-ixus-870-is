// Ghidra headless script to investigate JPCORE input configuration
// Goal: Find why JPCORE hardware encoder is configured but never produces output.
// Hypothesis: JPCORE input (source data / input DMA) is never configured.
//
// Run with: analyzeHeadless <project_dir> <project_name> -process PRIMARY.BIN -noanalysis
//           -scriptPath <dir> -postScript DecompileJPCOREInput.java
//
//@category CHDK
//@author webcam-re

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.io.FileWriter;
import java.io.File;
import java.util.Set;
import java.util.TreeSet;
import java.util.HashSet;
import java.util.Map;
import java.util.TreeMap;
import java.util.ArrayList;
import java.util.List;

public class DecompileJPCOREInput extends GhidraScript {

    private DecompInterface decomp;
    private StringBuilder output;

    // =====================================================================
    // PART 1: Specific functions to decompile
    // =====================================================================
    private static final long[] TARGET_ADDRS = {
        0xFF9E8104L, // FUN_ff9e8104 - MjpegEncodingCheck (called in pipeline frame callback)
        0xFF8EF838L, // FUN_ff8ef838 - JPCORE config (dimensions, quality, strides)
        0xFF8EB574L, // FUN_ff8eb574 - PipelineStep3 (full decompilation)
        0xFF8EED74L, // FUN_ff8eed74 - PipelineStep0 (resizer/color conversion)
        0xFF8C3BFCL, // sub_FF8C3BFC - Recording pipeline setup (called by movie_record_task)
        0xFF92FE8CL, // sub_FF92FE8C - Movie frame getter (4 output pointers)
        0xFF8C4208L, // FUN_ff8c4208 - DMA trigger function (one-shot DMA capture)
        0xFF9E8190L, // FUN_ff9e8190 - JPCORE enable (called by StartMjpegMaking_inner)
        0xFF9E81A0L, // FUN_ff9e81a0 - JPCORE disable
        0xFF8C4288L, // FUN_ff8c4288 - MJPEG active check
        0xFF8C2ED8L, // FUN_ff8c2ed8 - Called by StartEVFMovVGA_setup (FUN_ff8c3c64)
        0xFF8C4C60L, // FUN_ff8c4c60 - Called at start of StartEVFMovVGA
    };

    private static final String[] TARGET_NAMES = {
        "FUN_ff9e8104_MjpegEncodingCheck",
        "FUN_ff8ef838_JPCORE_Config",
        "FUN_ff8eb574_PipelineStep3",
        "FUN_ff8eed74_PipelineStep0_Resizer",
        "sub_FF8C3BFC_RecordingPipelineSetup",
        "sub_FF92FE8C_MovieFrameGetter",
        "FUN_ff8c4208_DMA_Trigger",
        "FUN_ff9e8190_JPCORE_Enable",
        "FUN_ff9e81a0_JPCORE_Disable",
        "FUN_ff8c4288_MJPEG_ActiveCheck",
        "FUN_ff8c2ed8_EVF_Setup_Inner",
        "FUN_ff8c4c60_EVF_PreSetup",
    };

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        // Increase timeout for complex functions
        decomp.setSimplificationStyle("decompile");

        output = new StringBuilder();
        output.append("========================================================================\n");
        output.append("JPCORE Input Configuration Investigation\n");
        output.append("Firmware: IXUS 870 IS / SD 880 IS, version 1.01a\n");
        output.append("Goal: Find why JPCORE HW encoder produces no output (input not configured?)\n");
        output.append("========================================================================\n\n");

        // PART 1: Decompile target functions
        output.append("########################################################################\n");
        output.append("# PART 1: Target Function Decompilation\n");
        output.append("########################################################################\n\n");

        for (int i = 0; i < TARGET_ADDRS.length; i++) {
            decompileFunction(TARGET_ADDRS[i], TARGET_NAMES[i]);
        }

        // PART 2: Find cross-references to FUN_ff8ef838 (JPCORE Config)
        output.append("\n########################################################################\n");
        output.append("# PART 2: Cross-references to FUN_ff8ef838 (JPCORE Config)\n");
        output.append("# Finding ALL callers to understand when JPCORE encoding params are set\n");
        output.append("########################################################################\n\n");

        findAndDecompileCallers(0xFF8EF838L, "FUN_ff8ef838_JPCORE_Config");

        // PART 3: Search for functions referencing JPCORE encoder registers 0xC0E10000-0xC0E1FFFF
        output.append("\n########################################################################\n");
        output.append("# PART 3: Functions referencing I/O registers 0xC0E10000-0xC0E1FFFF\n");
        output.append("# (Potential JPCORE encoder core registers)\n");
        output.append("########################################################################\n\n");

        searchIORegisterReferences(0xC0E10000L, 0xC0E1FFFFL, "JPCORE_Encoder_Core");

        // PART 4: Search for functions referencing 0xC0F04800-0xC0F048FF (before JPCORE DMA)
        output.append("\n########################################################################\n");
        output.append("# PART 4: Functions referencing I/O registers 0xC0F04800-0xC0F048FF\n");
        output.append("# (Register block before JPCORE DMA at 0xC0F04900)\n");
        output.append("########################################################################\n\n");

        searchIORegisterReferences(0xC0F04800L, 0xC0F048FFL, "JPCORE_PreDMA_Block");

        // PART 5: Also search 0xC0F04900-0xC0F049FF for completeness (known JPCORE DMA)
        output.append("\n########################################################################\n");
        output.append("# PART 5: Functions referencing I/O registers 0xC0F04900-0xC0F049FF\n");
        output.append("# (Known JPCORE DMA registers)\n");
        output.append("########################################################################\n\n");

        searchIORegisterReferences(0xC0F04900L, 0xC0F049FFL, "JPCORE_DMA_Block");

        // PART 6: Search for other potentially relevant register ranges
        output.append("\n########################################################################\n");
        output.append("# PART 6: Functions referencing I/O registers 0xC0E20000-0xC0E2FFFF\n");
        output.append("# (Potential image processing / resizer registers)\n");
        output.append("########################################################################\n\n");

        searchIORegisterReferences(0xC0E20000L, 0xC0E2FFFFL, "ImageProc_Resizer");

        // PART 7: Cross-references to FUN_ff9e8190 (JPCORE Enable) - who else calls it?
        output.append("\n########################################################################\n");
        output.append("# PART 7: Cross-references to FUN_ff9e8190 (JPCORE Enable)\n");
        output.append("# Finding ALL callers to see full initialization paths\n");
        output.append("########################################################################\n\n");

        findCallerList(0xFF9E8190L, "FUN_ff9e8190_JPCORE_Enable");

        // PART 8: Cross-references to sub_FF8C3BFC (Recording Pipeline Setup)
        output.append("\n########################################################################\n");
        output.append("# PART 8: Cross-references to sub_FF8C3BFC (Recording Pipeline Setup)\n");
        output.append("########################################################################\n\n");

        findCallerList(0xFF8C3BFCL, "sub_FF8C3BFC_RecordingPipelineSetup");

        // PART 9: Decompile functions called BY FUN_ff9e8190 (JPCORE Enable)
        // to understand what registers it actually configures
        output.append("\n########################################################################\n");
        output.append("# PART 9: Functions called by JPCORE Enable/Disable\n");
        output.append("# Decompiling callees to find register writes\n");
        output.append("########################################################################\n\n");

        decompileCallees(0xFF9E8190L, "FUN_ff9e8190_JPCORE_Enable", 2);

        // Write output
        String outputPath = "C:/projects/ixus870IS/firmware-analysis/jpcore_input_decompiled.txt";
        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\nOutput written to: " + outputPath);
        println("Total output size: " + output.length() + " chars");
    }

    /**
     * Decompile a single function by address and append to output
     */
    private void decompileFunction(long addr, String name) {
        try {
            Address address = toAddr(addr);
            println("Decompiling " + name + " at " + address + "...");

            Function func = getFunctionAt(address);
            if (func == null) {
                func = createFunction(address, name);
            }
            if (func == null) {
                output.append("// ERROR: Could not find or create function " + name + " at 0x" +
                    Long.toHexString(addr).toUpperCase() + "\n\n");
                return;
            }

            // Set name
            try {
                func.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED);
            } catch (Exception e) {
                // Name might already exist, ignore
            }

            DecompileResults results = decomp.decompileFunction(func, 120, monitor);
            if (results == null || !results.decompileCompleted()) {
                output.append("// ERROR: Decompilation failed for " + name + " at 0x" +
                    Long.toHexString(addr).toUpperCase() + "\n\n");
                return;
            }

            DecompiledFunction decompFunc = results.getDecompiledFunction();
            if (decompFunc == null) {
                output.append("// ERROR: No decompiled output for " + name + " at 0x" +
                    Long.toHexString(addr).toUpperCase() + "\n\n");
                return;
            }

            String sig = decompFunc.getSignature();
            String code = decompFunc.getC();

            output.append("// === " + name + " @ 0x" + Long.toHexString(addr).toUpperCase() + " ===\n");
            output.append("// Signature: " + sig + "\n");
            output.append("// Body size: " + func.getBody().getNumAddresses() + " bytes\n");
            output.append(code);
            output.append("\n\n");
        } catch (Exception e) {
            output.append("// EXCEPTION decompiling " + name + " at 0x" +
                Long.toHexString(addr).toUpperCase() + ": " + e.getMessage() + "\n\n");
        }
    }

    /**
     * Find all callers of a function and decompile each caller
     */
    private void findAndDecompileCallers(long targetAddr, String targetName) {
        try {
            Address address = toAddr(targetAddr);
            Function targetFunc = getFunctionAt(address);
            if (targetFunc == null) {
                targetFunc = createFunction(address, targetName);
            }

            ReferenceManager refMgr = currentProgram.getReferenceManager();
            ReferenceIterator refIter = refMgr.getReferencesTo(address);

            List<Address> callerAddrs = new ArrayList<>();
            Set<String> seenFunctions = new HashSet<>();

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                Function callerFunc = getFunctionContaining(fromAddr);
                if (callerFunc != null) {
                    String key = callerFunc.getEntryPoint().toString();
                    if (!seenFunctions.contains(key)) {
                        seenFunctions.add(key);
                        callerAddrs.add(callerFunc.getEntryPoint());
                    }
                }
            }

            output.append("// Found " + callerAddrs.size() + " callers of " + targetName + ":\n");
            for (Address a : callerAddrs) {
                Function f = getFunctionAt(a);
                output.append("//   - " + (f != null ? f.getName() : "unknown") + " @ " + a + "\n");
            }
            output.append("\n");

            // Decompile each caller
            for (Address callerAddr : callerAddrs) {
                Function callerFunc = getFunctionAt(callerAddr);
                String callerName = callerFunc != null ? callerFunc.getName() : "FUN_" + callerAddr;
                decompileFunction(callerAddr.getOffset(), "Caller_" + callerName);
            }

        } catch (Exception e) {
            output.append("// EXCEPTION finding callers of " + targetName + ": " + e.getMessage() + "\n\n");
        }
    }

    /**
     * Find all callers of a function and list them (without decompiling)
     */
    private void findCallerList(long targetAddr, String targetName) {
        try {
            Address address = toAddr(targetAddr);
            Function targetFunc = getFunctionAt(address);
            if (targetFunc == null) {
                targetFunc = createFunction(address, targetName);
            }

            ReferenceManager refMgr = currentProgram.getReferenceManager();
            ReferenceIterator refIter = refMgr.getReferencesTo(address);

            Set<String> seenFunctions = new HashSet<>();
            int count = 0;

            output.append("// Callers of " + targetName + " @ 0x" + Long.toHexString(targetAddr).toUpperCase() + ":\n");

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                Function callerFunc = getFunctionContaining(fromAddr);
                if (callerFunc != null) {
                    String key = callerFunc.getEntryPoint().toString();
                    if (!seenFunctions.contains(key)) {
                        seenFunctions.add(key);
                        output.append("//   " + callerFunc.getName() + " @ " + callerFunc.getEntryPoint() +
                            " (call site: " + fromAddr + ")\n");
                        count++;
                    }
                } else {
                    output.append("//   <no function> call site: " + fromAddr +
                        " (ref type: " + ref.getReferenceType() + ")\n");
                    count++;
                }
            }

            output.append("// Total: " + count + " unique callers\n\n");

        } catch (Exception e) {
            output.append("// EXCEPTION finding callers of " + targetName + ": " + e.getMessage() + "\n\n");
        }
    }

    /**
     * Search for functions that reference I/O registers in a given address range.
     * Scans the firmware ROM for 32-bit constants in the target range.
     */
    private void searchIORegisterReferences(long rangeStart, long rangeEnd, String regionName) {
        try {
            Memory mem = currentProgram.getMemory();
            MemoryBlock romBlock = null;

            // Find the ROM block (0xFF800000+)
            for (MemoryBlock block : mem.getBlocks()) {
                if (block.getStart().getOffset() >= 0xFF800000L) {
                    romBlock = block;
                    break;
                }
            }

            if (romBlock == null) {
                output.append("// ERROR: Could not find ROM memory block\n\n");
                return;
            }

            println("Scanning ROM for I/O register references in range 0x" +
                Long.toHexString(rangeStart).toUpperCase() + " - 0x" +
                Long.toHexString(rangeEnd).toUpperCase() + " (" + regionName + ")...");

            // Scan ROM for 32-bit values in the target range
            // We scan the literal pool (data referenced by LDR instructions)
            Address scanStart = romBlock.getStart();
            Address scanEnd = romBlock.getEnd();
            long startOff = scanStart.getOffset();
            long endOff = scanEnd.getOffset();

            // Map: register address -> list of code locations referencing it
            TreeMap<Long, List<String>> registerRefs = new TreeMap<>();
            Set<String> functionsFound = new TreeSet<>();

            // Scan every 4-byte aligned position in ROM for constants
            for (long pos = startOff; pos < endOff - 3; pos += 4) {
                try {
                    Address addr = toAddr(pos);
                    int val = mem.getInt(addr);
                    long uval = val & 0xFFFFFFFFL;

                    if (uval >= rangeStart && uval <= rangeEnd) {
                        // Found a reference to our target register range
                        // Find what references THIS address (i.e., what LDR instruction loads this constant)
                        ReferenceManager refMgr = currentProgram.getReferenceManager();
                        ReferenceIterator refIter = refMgr.getReferencesTo(addr);

                        while (refIter.hasNext()) {
                            Reference ref = refIter.next();
                            Address fromAddr = ref.getFromAddress();
                            Function func = getFunctionContaining(fromAddr);

                            String location;
                            if (func != null) {
                                location = func.getName() + " @ " + func.getEntryPoint() +
                                    " (instruction at " + fromAddr + ")";
                                functionsFound.add(func.getEntryPoint().toString() + "|" + func.getName());
                            } else {
                                location = "<no function> at " + fromAddr;
                            }

                            List<String> refs = registerRefs.get(uval);
                            if (refs == null) {
                                refs = new ArrayList<>();
                                registerRefs.put(uval, refs);
                            }
                            refs.add(location);
                        }

                        // Even if no xrefs to the literal pool entry, note the constant
                        if (!registerRefs.containsKey(uval)) {
                            List<String> refs = new ArrayList<>();
                            refs.add("(constant at ROM 0x" + Long.toHexString(pos).toUpperCase() +
                                ", no direct xrefs found)");
                            registerRefs.put(uval, refs);
                        }
                    }
                } catch (Exception e) {
                    // Skip unreadable addresses
                }
            }

            // Output results
            if (registerRefs.isEmpty()) {
                output.append("// No references to registers in range 0x" +
                    Long.toHexString(rangeStart).toUpperCase() + " - 0x" +
                    Long.toHexString(rangeEnd).toUpperCase() + " found.\n\n");
                return;
            }

            output.append("// Register references found (" + regionName + "):\n");
            output.append("// Unique registers: " + registerRefs.size() + "\n");
            output.append("// Unique functions: " + functionsFound.size() + "\n\n");

            for (Map.Entry<Long, List<String>> entry : registerRefs.entrySet()) {
                output.append("// Register 0x" + Long.toHexString(entry.getKey()).toUpperCase() + ":\n");
                for (String ref : entry.getValue()) {
                    output.append("//   Referenced by: " + ref + "\n");
                }
            }
            output.append("\n");

            // Decompile unique functions that reference these registers (limit to 15 to keep output manageable)
            int decompCount = 0;
            for (String funcInfo : functionsFound) {
                if (decompCount >= 15) {
                    output.append("// ... truncated (" + (functionsFound.size() - decompCount) +
                        " more functions not decompiled)\n\n");
                    break;
                }
                String[] parts = funcInfo.split("\\|");
                long funcAddr = Long.parseLong(parts[0].replace("ff", "FF").replace("0x", ""), 16);
                // Parse the address properly
                Address a = toAddr(parts[0]);
                Function f = getFunctionAt(a);
                if (f != null) {
                    decompileFunction(a.getOffset(), regionName + "_" + f.getName());
                    decompCount++;
                }
            }

        } catch (Exception e) {
            output.append("// EXCEPTION searching for " + regionName + " register references: " +
                e.getMessage() + "\n\n");
        }
    }

    /**
     * Decompile functions called by a given function (1 level deep, or deeper)
     */
    private void decompileCallees(long funcAddr, String funcName, int maxDepth) {
        try {
            Address address = toAddr(funcAddr);
            Function func = getFunctionAt(address);
            if (func == null) {
                output.append("// ERROR: Function not found at " + address + "\n\n");
                return;
            }

            Set<String> visited = new HashSet<>();
            decompileCalleesRecursive(func, funcName, 0, maxDepth, visited);

        } catch (Exception e) {
            output.append("// EXCEPTION in decompileCallees for " + funcName + ": " + e.getMessage() + "\n\n");
        }
    }

    private void decompileCalleesRecursive(Function func, String parentName, int depth, int maxDepth, Set<String> visited) {
        if (depth >= maxDepth) return;

        String funcKey = func.getEntryPoint().toString();
        if (visited.contains(funcKey)) return;
        visited.add(funcKey);

        // Get all called functions
        Set<Function> calledFunctions = func.getCalledFunctions(monitor);

        String indent = "";
        for (int i = 0; i < depth; i++) indent += "  ";

        output.append("// " + indent + "Callees of " + parentName + " @ " + func.getEntryPoint() + ":\n");

        for (Function callee : calledFunctions) {
            // Skip thunks to well-known OS functions
            Address calleeAddr = callee.getEntryPoint();
            long offset = calleeAddr.getOffset();

            output.append("// " + indent + "  -> " + callee.getName() + " @ " + calleeAddr + "\n");

            // Decompile if it's in firmware ROM range and not a trivial OS function
            if (offset >= 0xFF800000L && !visited.contains(calleeAddr.toString())) {
                decompileFunction(offset, indent + "Callee_" + callee.getName());
                // Recurse
                decompileCalleesRecursive(callee, callee.getName(), depth + 1, maxDepth, visited);
            }
        }
    }
}
