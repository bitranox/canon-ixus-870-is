// Ghidra headless script - Resolve Phase 2 DAT_ references
//
//@category CHDK
//@author webcam-re

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import java.io.FileWriter;

public class ResolveDAT2 extends GhidraScript {

    private static final long[][] DAT_LIST = {
        // VideoRecPipelineSetup registers
        {0xffa04960L}, // param_2 (mode)
        {0xffa04964L}, // block write base (7 regs)
        {0xffa04968L}, // local_34
        {0xffa0496cL}, // local_30
        {0xffa04970L}, // local_2c
        {0xffa04974L}, // local_28
        {0xffa04978L}, // local_54

        // ISPSensorConfig registers
        {0xffa9a1e0L}, // puVar1 base struct
        {0xffa9a1e4L}, // written with uVar2*0x10 & 0xf0 | 1
        {0xffa9a1e8L}, // written with (param_6 + puVar1[1]) * 0x10000 ...
        {0xffa9a1ecL}, // written with pipeline config

        // ISPColorMatrix registers
        {0xffa9a198L}, // param_1
        {0xffa9a19cL}, // param_2

        // ISPConfigArray registers
        {0xffa9a1f0L}, // array1
        {0xffa9a1f4L}, // array1 part2
        {0xffa9a1f8L}, // array2 (written 0)

        // Resolution query data tables
        {0xff9e8620L}, // mode 4 resolution table
        {0xff9e8624L}, // constant
        {0xff9e8628L}, // mode 5 resolution table

        // FFA03A60 constant in VideoRecPipelineSetup
        {0xffa03a60L},

        // FFA028D0 - called from VideoRecPipelineSetup
        // JPCORE disable state
        {0xff9e8238L}, // state pointer
        {0xff9e8234L}, // timeout/flag
        {0xff9e8254L}, // line number for assert

        // ISPSensorConfig sub-functions
        // FFA99BD8 - called from ISPSensorConfig
        // FFA99AFC - called from ISPSensorConfig
    };

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        StringBuilder output = new StringBuilder();

        output.append("========================================================================\n");
        output.append("DAT_ Reference Resolution - Phase 2\n");
        output.append("Firmware: IXUS 870 IS / SD 880 IS, version 1.01a\n");
        output.append("========================================================================\n\n");

        for (long[] entry : DAT_LIST) {
            long addr = entry[0];
            Address a = toAddr(addr);
            try {
                int val = mem.getInt(a);
                long uval = val & 0xFFFFFFFFL;
                String interp = interpretValue(uval);
                output.append(String.format("DAT_%08X  =>  0x%08X  %s\n", addr, uval, interp));

                // Follow ROM pointers
                if (uval >= 0xFF800000L && uval <= 0xFFFFFFFFL) {
                    Address valAddr = toAddr(uval);
                    try {
                        int inner = mem.getInt(valAddr);
                        long innerU = inner & 0xFFFFFFFFL;
                        output.append(String.format("              ->  *0x%08X = 0x%08X  %s\n", uval, innerU, interpretValue(innerU)));
                    } catch (Exception e) {}
                }
            } catch (Exception e) {
                output.append(String.format("DAT_%08X  =>  READ FAILED\n", addr));
            }
        }

        // Resolve VideoRecPipelineSetup register block
        output.append("\n========================================================================\n");
        output.append("VideoRecPipelineSetup Register Block (DAT_ffa04964 base + 0..6*4)\n");
        output.append("========================================================================\n\n");

        try {
            long blockBase = mem.getInt(toAddr(0xffa04964L)) & 0xFFFFFFFFL;
            output.append(String.format("Block base: 0x%08X  %s\n\n", blockBase, interpretValue(blockBase)));
            // FUN_ff822b18 writes 7 consecutive uint32s starting at this address
            for (int i = 0; i < 10; i++) {
                long regAddr = blockBase + i * 4;
                output.append(String.format("  [%d] 0x%08X  %s\n", i, regAddr, interpretValue(regAddr)));
            }
        } catch (Exception e) {
            output.append("Failed: " + e.getMessage() + "\n");
        }

        // Resolve resolution tables
        output.append("\n========================================================================\n");
        output.append("Resolution Tables\n");
        output.append("========================================================================\n\n");

        try {
            long table4 = mem.getInt(toAddr(0xff9e8620L)) & 0xFFFFFFFFL;
            long table5 = mem.getInt(toAddr(0xff9e8628L)) & 0xFFFFFFFFL;
            output.append(String.format("Mode 4 (EVF) table: 0x%08X\n", table4));
            output.append(String.format("Mode 5 (Rec) table: 0x%08X\n\n", table5));

            // Each entry is 4 bytes (2 x uint16: width, height), param_4 selects the entry
            if (table4 >= 0xFF800000L) {
                output.append("Mode 4 entries (4 bytes each = 2x uint16):\n");
                for (int i = 0; i < 4; i++) {
                    long entryAddr = table4 + i * 4;
                    int entryVal = mem.getInt(toAddr(entryAddr));
                    int w = entryVal & 0xFFFF;
                    int h = (entryVal >> 16) & 0xFFFF;
                    output.append(String.format("  [%d] 0x%08X: raw=0x%08X  w=%d h=%d\n", i, entryAddr, entryVal & 0xFFFFFFFFL, w, h));
                }
            }

            if (table5 >= 0xFF800000L) {
                output.append("Mode 5 entries:\n");
                for (int i = 0; i < 4; i++) {
                    long entryAddr = table5 + i * 4;
                    int entryVal = mem.getInt(toAddr(entryAddr));
                    int w = entryVal & 0xFFFF;
                    int h = (entryVal >> 16) & 0xFFFF;
                    output.append(String.format("  [%d] 0x%08X: raw=0x%08X  w=%d h=%d\n", i, entryAddr, entryVal & 0xFFFFFFFFL, w, h));
                }
            }
        } catch (Exception e) {
            output.append("Failed: " + e.getMessage() + "\n");
        }

        // Resolve the ISPSensorConfig RAM structure
        output.append("\n========================================================================\n");
        output.append("ISPSensorConfig Structure (DAT_ffa9a1e0)\n");
        output.append("========================================================================\n\n");

        try {
            long structBase = mem.getInt(toAddr(0xffa9a1e0L)) & 0xFFFFFFFFL;
            output.append(String.format("Structure base: 0x%08X  %s\n", structBase, interpretValue(structBase)));
        } catch (Exception e) {
            output.append("Failed\n");
        }

        // Write output
        String outputPath = "C:/projects/ixus870IS/firmware-analysis/isp_dat_resolved2.txt";
        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\nPhase 2 DAT resolution output written to: " + outputPath);
        println("\n" + output.toString());
    }

    private String interpretValue(long val) {
        if (val >= 0xC0F00000L && val <= 0xC0F0FFFFL) return "*** ISP Register ***";
        if (val >= 0xC0F10000L && val <= 0xC0F1FFFFL) return "*** JPCORE Register ***";
        if (val >= 0xC0E00000L && val <= 0xC0EFFFFFL) return "*** Image Pipe Register ***";
        if (val >= 0xC0F20000L && val <= 0xC0FFFFFFL) return "*** Other I/O Register ***";
        if (val >= 0xC0000000L && val <= 0xC0DFFFFFL) return "Hardware I/O";
        if (val >= 0xFF800000L && val <= 0xFFFFFFFFL) return "ROM";
        if (val >= 0x40000000L && val <= 0x43FFFFFFL) return "Uncached RAM";
        if (val >= 0x00000000L && val <= 0x03FFFFFFL) return "RAM";
        if (val >= 0x10000000L && val <= 0x1FFFFFFFL) return "TCM/Cache";
        return "";
    }
}
