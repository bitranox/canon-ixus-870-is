// Ghidra headless script to decompile EVF display path functions
// and sub-functions that access ISP/JPCORE registers (0xC0F0xxxx - 0xC0F1xxxx)
//
// Run with: analyzeHeadless <project_dir> <project_name> -process PRIMARY.BIN -noanalysis
//           -scriptPath <dir> -postScript DecompileEVFPath.java
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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.HighFunction;
import java.io.FileWriter;
import java.io.File;
import java.util.*;

public class DecompileEVFPath extends GhidraScript {

    // Primary target functions
    private static final long[] PRIMARY_ADDRS = {
        0xFF9E51D8L, // FUN_ff9e51d8 - EVF display path (counterpart to VideoRecPath)
        0xFF9E8104L, // FUN_ff9e8104 - MjpegEncodingCheck (called before FrameProcessing)
    };

    private static final String[] PRIMARY_NAMES = {
        "FUN_ff9e51d8_EVFDisplayPath",
        "FUN_ff9e8104_MjpegEncodingCheck",
    };

    // ISP/JPCORE register range: 0xC0F00000 - 0xC0F1FFFF
    private static final long ISP_REG_BASE  = 0xC0F00000L;
    private static final long ISP_REG_END   = 0xC0F1FFFFL;

    private DecompInterface decomp;
    private StringBuilder output;
    private Set<Long> decompiled = new HashSet<>(); // track already-decompiled addresses

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        output = new StringBuilder();
        output.append("========================================================================\n");
        output.append("EVF Display Path & MJPEG Encoding Check — Decompilation\n");
        output.append("Firmware: IXUS 870 IS / SD 880 IS, version 1.01a\n");
        output.append("========================================================================\n\n");

        // ---------------------------------------------------------------
        // Part 1: Decompile the two primary target functions
        // ---------------------------------------------------------------
        output.append("========================================================================\n");
        output.append("PART 1: Primary Target Functions\n");
        output.append("========================================================================\n\n");

        for (int i = 0; i < PRIMARY_ADDRS.length; i++) {
            decompileAndAppend(PRIMARY_ADDRS[i], PRIMARY_NAMES[i]);
        }

        // ---------------------------------------------------------------
        // Part 2: Find all functions called by FUN_ff9e51d8 (EVF path)
        // ---------------------------------------------------------------
        output.append("========================================================================\n");
        output.append("PART 2: Functions Called by FUN_ff9e51d8 (EVF Display Path)\n");
        output.append("========================================================================\n\n");

        List<Long> evfCallTargets = getCallTargets(0xFF9E51D8L);
        output.append("// FUN_ff9e51d8 calls " + evfCallTargets.size() + " functions:\n");
        for (Long target : evfCallTargets) {
            output.append("//   " + String.format("0x%08X", target) + "\n");
        }
        output.append("\n");

        // Decompile each called function
        for (Long target : evfCallTargets) {
            if (!decompiled.contains(target)) {
                String name = getFuncName(target);
                decompileAndAppend(target, name);
            }
        }

        // ---------------------------------------------------------------
        // Part 3: Find sub-functions that write ISP/JPCORE registers
        // Recursively scan call targets of EVF path + its direct callees
        // ---------------------------------------------------------------
        output.append("========================================================================\n");
        output.append("PART 3: Sub-functions Writing ISP/JPCORE Registers (0xC0F0xxxx-0xC0F1xxxx)\n");
        output.append("========================================================================\n\n");

        // Collect all addresses to scan (EVF path + its direct callees)
        Set<Long> toScan = new LinkedHashSet<>();
        toScan.add(0xFF9E51D8L);
        toScan.addAll(evfCallTargets);

        // Now scan their callees (2 levels deep) for ISP register access
        Set<Long> level2Targets = new LinkedHashSet<>();
        for (Long addr : toScan) {
            List<Long> subCalls = getCallTargets(addr);
            level2Targets.addAll(subCalls);
        }

        // Also scan level 3 (callees of callees of callees)
        Set<Long> level3Targets = new LinkedHashSet<>();
        for (Long addr : level2Targets) {
            List<Long> subCalls = getCallTargets(addr);
            level3Targets.addAll(subCalls);
        }

        // Combine all candidate functions
        Set<Long> allCandidates = new LinkedHashSet<>();
        allCandidates.addAll(toScan);
        allCandidates.addAll(level2Targets);
        allCandidates.addAll(level3Targets);

        // Check each candidate for ISP register references
        List<Long> ispFunctions = new ArrayList<>();
        for (Long addr : allCandidates) {
            if (decompiled.contains(addr)) continue;
            if (accessesISPRegisters(addr)) {
                ispFunctions.add(addr);
            }
        }

        output.append("// Found " + ispFunctions.size() + " sub-functions accessing ISP/JPCORE registers\n\n");

        for (Long addr : ispFunctions) {
            if (!decompiled.contains(addr)) {
                String name = getFuncName(addr);
                decompileAndAppend(addr, name + " [ISP/JPCORE]");
            }
        }

        // ---------------------------------------------------------------
        // Part 4: Also decompile FUN_ff9e8104's callees for completeness
        // ---------------------------------------------------------------
        output.append("========================================================================\n");
        output.append("PART 4: Functions Called by FUN_ff9e8104 (MjpegEncodingCheck)\n");
        output.append("========================================================================\n\n");

        List<Long> mjpegCheckCallTargets = getCallTargets(0xFF9E8104L);
        output.append("// FUN_ff9e8104 calls " + mjpegCheckCallTargets.size() + " functions:\n");
        for (Long target : mjpegCheckCallTargets) {
            output.append("//   " + String.format("0x%08X", target) + "\n");
        }
        output.append("\n");

        for (Long target : mjpegCheckCallTargets) {
            if (!decompiled.contains(target)) {
                String name = getFuncName(target);
                decompileAndAppend(target, name);
            }
        }

        // ---------------------------------------------------------------
        // Write output
        // ---------------------------------------------------------------
        String outputPath = "C:/projects/ixus870IS/firmware-analysis/evf_path_decompiled.txt";
        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\nDecompilation output written to: " + outputPath);
        println("\n" + output.toString());
    }

    /**
     * Decompile a function and append to output buffer.
     */
    private void decompileAndAppend(long addr, String label) {
        if (decompiled.contains(addr)) return;
        decompiled.add(addr);

        try {
            Address address = toAddr(addr);
            println("Decompiling " + label + " at " + address + "...");

            Function func = getFunctionAt(address);
            if (func == null) {
                func = createFunction(address, null);
            }
            if (func == null) {
                output.append("// Could not find or create function " + label + " at " +
                              String.format("0x%08X", addr) + "\n\n");
                return;
            }

            DecompileResults results = decomp.decompileFunction(func, 120, monitor);
            if (results == null || !results.decompileCompleted()) {
                output.append("// Decompilation failed for " + label + " at " +
                              String.format("0x%08X", addr) + "\n\n");
                return;
            }

            DecompiledFunction decompFunc = results.getDecompiledFunction();
            if (decompFunc == null) {
                output.append("// No decompiled output for " + label + " at " +
                              String.format("0x%08X", addr) + "\n\n");
                return;
            }

            String sig = decompFunc.getSignature();
            String code = decompFunc.getC();

            output.append("// === " + label + " @ " + String.format("0x%08X", addr) + " ===\n");
            output.append("// Function name in Ghidra: " + func.getName() + "\n");
            output.append("// Signature: " + sig + "\n");
            output.append(code);
            output.append("\n\n");
        } catch (Exception e) {
            output.append("// Exception decompiling " + label + " at " +
                          String.format("0x%08X", addr) + ": " + e.getMessage() + "\n\n");
        }
    }

    /**
     * Get all call targets (BL instruction destinations) from a function.
     */
    private List<Long> getCallTargets(long funcAddr) {
        List<Long> targets = new ArrayList<>();
        try {
            Address address = toAddr(funcAddr);
            Function func = getFunctionAt(address);
            if (func == null) return targets;

            AddressSetView body = func.getBody();
            InstructionIterator instIter = currentProgram.getListing().getInstructions(body, true);
            Set<Long> seen = new HashSet<>();

            while (instIter.hasNext()) {
                Instruction inst = instIter.next();
                String mnemonic = inst.getMnemonicString();
                // Look for BL (branch-and-link) = function calls
                if (mnemonic.equals("bl") || mnemonic.equals("BL")) {
                    Reference[] refs = inst.getReferencesFrom();
                    for (Reference ref : refs) {
                        if (ref.getReferenceType().isCall()) {
                            long targetAddr = ref.getToAddress().getOffset();
                            if (!seen.contains(targetAddr)) {
                                seen.add(targetAddr);
                                targets.add(targetAddr);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            println("Error getting call targets for " + String.format("0x%08X", funcAddr) + ": " + e.getMessage());
        }
        return targets;
    }

    /**
     * Check if a function accesses ISP/JPCORE registers (0xC0F00000-0xC0F1FFFF).
     * We scan the instruction bytes for references to addresses in that range.
     */
    private boolean accessesISPRegisters(long funcAddr) {
        try {
            Address address = toAddr(funcAddr);
            Function func = getFunctionAt(address);
            if (func == null) {
                // Try to create it
                func = createFunction(address, null);
            }
            if (func == null) return false;

            AddressSetView body = func.getBody();
            InstructionIterator instIter = currentProgram.getListing().getInstructions(body, true);

            while (instIter.hasNext()) {
                Instruction inst = instIter.next();
                // Check all references from this instruction
                Reference[] refs = inst.getReferencesFrom();
                for (Reference ref : refs) {
                    long refAddr = ref.getToAddress().getOffset();
                    if (refAddr >= ISP_REG_BASE && refAddr <= ISP_REG_END) {
                        return true;
                    }
                }
                // Also check instruction operands for embedded constants
                // ARM often loads constants from a literal pool
                for (int i = 0; i < inst.getNumOperands(); i++) {
                    Object[] opObjs = inst.getOpObjects(i);
                    for (Object obj : opObjs) {
                        if (obj instanceof Address) {
                            long opAddr = ((Address) obj).getOffset();
                            if (opAddr >= ISP_REG_BASE && opAddr <= ISP_REG_END) {
                                return true;
                            }
                        } else if (obj instanceof ghidra.program.model.scalar.Scalar) {
                            long val = ((ghidra.program.model.scalar.Scalar) obj).getUnsignedValue();
                            if (val >= ISP_REG_BASE && val <= ISP_REG_END) {
                                return true;
                            }
                        }
                    }
                }
            }

            // Also check data references (literal pool values loaded by LDR)
            // Scan the function body bytes for 4-byte constants in the ISP range
            // This catches cases where LDR Rn, [PC, #offset] loads from a pool
            // that Ghidra may not create explicit references for
            InstructionIterator instIter2 = currentProgram.getListing().getInstructions(body, true);
            while (instIter2.hasNext()) {
                Instruction inst = instIter2.next();
                String mnemonic = inst.getMnemonicString().toLowerCase();
                if (mnemonic.startsWith("ldr")) {
                    // Check if any data reference from this instruction
                    // points to a literal pool entry containing an ISP address
                    Reference[] refs = inst.getReferencesFrom();
                    for (Reference ref : refs) {
                        if (ref.getReferenceType().isData()) {
                            Address dataAddr = ref.getToAddress();
                            try {
                                // Read the 4-byte value at the literal pool location
                                long poolVal = currentProgram.getMemory().getInt(dataAddr) & 0xFFFFFFFFL;
                                if (poolVal >= ISP_REG_BASE && poolVal <= ISP_REG_END) {
                                    return true;
                                }
                            } catch (Exception e) {
                                // ignore read errors
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            println("Error checking ISP access for " + String.format("0x%08X", funcAddr) + ": " + e.getMessage());
        }
        return false;
    }

    /**
     * Get a descriptive name for a function address.
     */
    private String getFuncName(long addr) {
        try {
            Address address = toAddr(addr);
            Function func = getFunctionAt(address);
            if (func != null) {
                return func.getName() + "_" + String.format("%08x", addr);
            }
        } catch (Exception e) {
            // ignore
        }
        return "FUN_" + String.format("%08x", addr);
    }
}
