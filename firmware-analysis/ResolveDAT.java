// Ghidra headless script to resolve DAT_ references from the ISP routing decompilation.
// Reads the 4-byte value stored at each ROM address to reveal actual hardware register addresses.
//
//@category CHDK
//@author webcam-re

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import java.io.FileWriter;

public class ResolveDAT extends GhidraScript {

    // All DAT_ references from the ISP routing decompilation
    private static final long[] DAT_ADDRS = {
        // From FUN_ff9e8190_JPCORE_enable
        0xff9e8250L,  // DAT_ff9e8250 - *DAT = 1 (JPCORE enable flag)

        // From sub_FF8C3BFC_RecPipelineSetup
        0xff8c2e24L,  // DAT_ff8c2e24 - MJPEG state structure base

        // From FUN_ff9e508c_VideoRecPath
        0xff9e5d28L,  // DAT_ff9e5d28
        0xff9e4e60L,  // DAT_ff9e4e60
        0xff9e5d2cL,  // DAT_ff9e5d2c - passed to DMAInterruptSetup
        0xff9e5d30L,  // DAT_ff9e5d30 - passed to JPCORE_RegisterCallback

        // From PipelineRouting_FF8EFA6C - CRITICAL for ISP routing
        0xff8f001cL,  // DAT_ff8f001c - base for param_1 >= 8
        0xff8f0020L,  // DAT_ff8f0020 - base for param_1 < 8

        // From FUN_ffa02ddc_PipelineResizer
        0xffa039e0L,  // DAT_ffa039e0
        0xffa039f0L,  // DAT_ffa039f0
        0xffa039f4L,  // DAT_ffa039f4
        0xffa039f8L,  // DAT_ffa039f8
        0xffa039fcL,  // DAT_ffa039fc

        // From FUN_ff8c335c_FrameDispatch
        0xff8c3d04L,  // DAT_ff8c3d04

        // From DMAInterruptSetup_FF9E4DF8
        0xff9e4e78L,  // DAT_ff9e4e78
        0xff8f000cL,  // DAT_ff8f000c - DMA channel base array
        0xff8f0010L,  // DAT_ff8f0010

        // From FUN_ff9e4ef0 (VideoRecPath sub)
        0xff9e4e64L,  // DAT_ff9e4e64
        0xff9e5d0cL,  // DAT_ff9e5d0c
        0xff9e5d10L,  // DAT_ff9e5d10
        0xff9e5d14L,  // DAT_ff9e5d14
        0xff9e5d18L,  // DAT_ff9e5d18
        0xff9e5d1cL,  // DAT_ff9e5d1c
        0xff9e5d20L,  // DAT_ff9e5d20
        0xff9e5d24L,  // DAT_ff9e5d24

        // From FUN_ffa0467c / FUN_ffa0473c
        0xffa049c0L,  // DAT_ffa049c0
        0xffa049c4L,  // DAT_ffa049c4
        0xffa049e0L,  // DAT_ffa049e0
        0xffa049e4L,  // DAT_ffa049e4

        // From PipelineScalerConfig2 / Config1 / FUN_ff8f7128
        0xff8f7310L,  // DAT_ff8f7310
        0xff8f730cL,  // DAT_ff8f730c
        0xff8f7314L,  // DAT_ff8f7314
        0xff8f731cL,  // DAT_ff8f731c

        // From FUN_ff8efabc_JPCORE_RegisterCallback
        0xff8f0024L,  // DAT_ff8f0024 - callback table

        // From FUN_ff8416c8
        0xff841100L,  // DAT_ff841100
    };

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        StringBuilder output = new StringBuilder();

        output.append("========================================================================\n");
        output.append("DAT_ Reference Resolution - ISP Routing Functions\n");
        output.append("Firmware: IXUS 870 IS / SD 880 IS, version 1.01a\n");
        output.append("========================================================================\n\n");
        output.append(String.format("%-14s  %-12s  %-12s  %s\n", "DAT Address", "Value (hex)", "Value (dec)", "Interpretation"));
        output.append(String.format("%-14s  %-12s  %-12s  %s\n", "-----------", "-----------", "-----------", "--------------"));

        for (long addr : DAT_ADDRS) {
            Address a = toAddr(addr);
            try {
                int val = mem.getInt(a);
                long uval = val & 0xFFFFFFFFL;
                String interp = interpretValue(uval);
                output.append(String.format("0x%08X  =>  0x%08X  %10d  %s\n", addr, uval, uval, interp));

                // If the value is a RAM pointer, try to read what it points to
                // (won't work for RAM, but will work for ROM pointers)
                if (uval >= 0xFF800000L && uval <= 0xFFFFFFFFL) {
                    Address valAddr = toAddr(uval);
                    try {
                        int innerVal = mem.getInt(valAddr);
                        long innerUval = innerVal & 0xFFFFFFFFL;
                        output.append(String.format("              ->  *0x%08X = 0x%08X  %s\n",
                            uval, innerUval, interpretValue(innerUval)));
                    } catch (Exception e) {
                        // Can't read
                    }
                }
            } catch (Exception e) {
                output.append(String.format("0x%08X  =>  READ FAILED: %s\n", addr, e.getMessage()));
            }
        }

        // Special: resolve the PipelineRouting register array
        output.append("\n========================================================================\n");
        output.append("PipelineRouting Register Array Resolution\n");
        output.append("========================================================================\n\n");

        // DAT_ff8f0020 is the base for param_1 < 8 (channels 0-7)
        // DAT_ff8f001c is the base for param_1 >= 8
        try {
            long base0_7 = mem.getInt(toAddr(0xff8f0020L)) & 0xFFFFFFFFL;
            long base8plus = mem.getInt(toAddr(0xff8f001cL)) & 0xFFFFFFFFL;

            output.append(String.format("Base for channels 0-7 (DAT_ff8f0020): 0x%08X\n", base0_7));
            output.append(String.format("Base for channels 8+ (DAT_ff8f001c):  0x%08X\n\n", base8plus));

            // For the call PipelineRouting_FF8EFA6C(0, 0x11):
            // param_1=0 < 8, so base = DAT_ff8f0020
            // addr = base + 0*4 = base
            long routingAddr = base0_7;
            output.append(String.format("PipelineRouting(0, 0x11):\n"));
            output.append(String.format("  Register address: base + 0*4 = 0x%08X\n", routingAddr));
            output.append(String.format("  Value written: 0x11\n"));
            output.append(String.format("  Interpretation: %s\n\n", interpretValue(routingAddr)));

            // Show all 8 channel addresses
            output.append("All routing channel registers (base + channel*4):\n");
            for (int ch = 0; ch < 16; ch++) {
                long chBase = (ch < 8) ? base0_7 : base8plus;
                long chAddr = chBase + ch * 4;
                output.append(String.format("  Channel %2d: 0x%08X  %s\n", ch, chAddr, interpretValue(chAddr)));
            }
        } catch (Exception e) {
            output.append("Failed to resolve: " + e.getMessage() + "\n");
        }

        // Resolve the DMA channel base array
        output.append("\n========================================================================\n");
        output.append("DMA Channel Base Array (DAT_ff8f000c)\n");
        output.append("========================================================================\n\n");

        try {
            long dmaBase = mem.getInt(toAddr(0xff8f000cL)) & 0xFFFFFFFFL;
            output.append(String.format("DMA base array at: 0x%08X\n", dmaBase));

            // Each entry is 0xC bytes (3 uint32s)
            if (dmaBase >= 0xFF800000L) {
                for (int ch = 0; ch < 4; ch++) {
                    long entryAddr = dmaBase + ch * 0xC;
                    try {
                        long v0 = mem.getInt(toAddr(entryAddr)) & 0xFFFFFFFFL;
                        long v1 = mem.getInt(toAddr(entryAddr + 4)) & 0xFFFFFFFFL;
                        long v2 = mem.getInt(toAddr(entryAddr + 8)) & 0xFFFFFFFFL;
                        output.append(String.format("  Channel %d @ 0x%08X: [0]=0x%08X [1]=0x%08X [2]=0x%08X\n",
                            ch, entryAddr, v0, v1, v2));
                        output.append(String.format("    [0] %s\n", interpretValue(v0)));
                        output.append(String.format("    [1] %s  (register base for DMA config)\n", interpretValue(v1)));
                        output.append(String.format("    [2] %s\n", interpretValue(v2)));
                    } catch (Exception e) {
                        output.append(String.format("  Channel %d: read failed\n", ch));
                    }
                }
            }
        } catch (Exception e) {
            output.append("Failed: " + e.getMessage() + "\n");
        }

        // Resolve the scaler/resizer registers
        output.append("\n========================================================================\n");
        output.append("Pipeline Scaler/Resizer Register Addresses\n");
        output.append("========================================================================\n\n");

        long[] scalerDATs = {0xff8f7310L, 0xff8f7314L, 0xff8f731cL, 0xff8f730cL};
        String[] scalerNames = {"ScalerConfig2 reg", "ScalerConfig1 reg", "FUN_ff8f7128 reg", "ScalerConfig2 base value"};
        for (int i = 0; i < scalerDATs.length; i++) {
            try {
                long val = mem.getInt(toAddr(scalerDATs[i])) & 0xFFFFFFFFL;
                output.append(String.format("DAT_%08X (%s): 0x%08X  %s\n",
                    scalerDATs[i], scalerNames[i], val, interpretValue(val)));
            } catch (Exception e) {
                output.append(String.format("DAT_%08X: read failed\n", scalerDATs[i]));
            }
        }

        // Resolve the FUN_ffa0467c / FUN_ffa0473c registers
        output.append("\n========================================================================\n");
        output.append("Pipeline Mode Registers (FFA046xx / FFA047xx)\n");
        output.append("========================================================================\n\n");

        long[] modeDATs = {0xffa049c0L, 0xffa049c4L, 0xffa049e0L, 0xffa049e4L};
        String[] modeNames = {"FFA0467C reg1", "FFA0467C reg2", "FFA0473C reg1", "FFA0473C reg2"};
        for (int i = 0; i < modeDATs.length; i++) {
            try {
                long val = mem.getInt(toAddr(modeDATs[i])) & 0xFFFFFFFFL;
                output.append(String.format("DAT_%08X (%s): 0x%08X  %s\n",
                    modeDATs[i], modeNames[i], val, interpretValue(val)));
            } catch (Exception e) {
                output.append(String.format("DAT_%08X: read failed\n", modeDATs[i]));
            }
        }

        // Resolve all the registers from FUN_ff9e4ef0
        output.append("\n========================================================================\n");
        output.append("ISP Setup Registers (FUN_ff9e4ef0 - called during video rec path)\n");
        output.append("========================================================================\n\n");

        long[] ispDATs = {0xff9e5d0cL, 0xff9e5d10L, 0xff9e5d14L, 0xff9e5d18L, 0xff9e5d1cL, 0xff9e5d20L, 0xff9e5d24L};
        String[] ispNames = {
            "ISP reg (written 0x80000000)",
            "ISP reg (written 0x1000)",
            "ISP reg (written 0)",
            "ISP reg (written 0)",
            "ISP reg (written 0x11 or 0x01)",
            "ISP reg (written 0 or 1)",
            "ISP reg (written 0x110 or 0x100)"
        };
        for (int i = 0; i < ispDATs.length; i++) {
            try {
                long val = mem.getInt(toAddr(ispDATs[i])) & 0xFFFFFFFFL;
                output.append(String.format("DAT_%08X (%s): 0x%08X  %s\n",
                    ispDATs[i], ispNames[i], val, interpretValue(val)));
            } catch (Exception e) {
                output.append(String.format("DAT_%08X: read failed\n", ispDATs[i]));
            }
        }

        // Resolve PipelineResizer registers
        output.append("\n========================================================================\n");
        output.append("PipelineResizer Registers (FUN_ffa02ddc)\n");
        output.append("========================================================================\n\n");

        long[] resDATs = {0xffa039e0L, 0xffa039f0L, 0xffa039f4L, 0xffa039f8L, 0xffa039fcL};
        String[] resNames = {"mode3 special value", "reg (written 1)", "reg (written param_2)", "reg (written param_3)", "reg (written uVar3)"};
        for (int i = 0; i < resDATs.length; i++) {
            try {
                long val = mem.getInt(toAddr(resDATs[i])) & 0xFFFFFFFFL;
                output.append(String.format("DAT_%08X (%s): 0x%08X  %s\n",
                    resDATs[i], resNames[i], val, interpretValue(val)));
            } catch (Exception e) {
                output.append(String.format("DAT_%08X: read failed\n", resDATs[i]));
            }
        }

        // Write output
        String outputPath = "C:/projects/ixus870IS/firmware-analysis/isp_dat_resolved.txt";
        FileWriter writer = new FileWriter(outputPath);
        writer.write(output.toString());
        writer.close();

        println("\nDAT resolution output written to: " + outputPath);
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
