// Decompile recording pipeline setup and DMA trigger functions
// @category CHDK

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.address.Address;

import java.io.FileWriter;
import java.io.PrintWriter;

public class DecompileRecPipeline extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outPath = "C:\\projects\\ixus870IS\\firmware-analysis\\rec_pipeline_decompiled.txt";
        PrintWriter out = new PrintWriter(new FileWriter(outPath));

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Functions to decompile
        String[][] targets = {
            {"0xFF8C3BFC", "RecPipelineSetup_FF8C3BFC"},
            {"0xFF8C4208", "DMA_Trigger_FF8C4208"},
            {"0xFF92FE8C", "MovieFrameGetter_FF92FE8C"},
            {"0xFF8C4288", "MjpegActiveCheck_FF8C4288"},
            {"0xFF8C425C", "StopContinuousVRAMData_FF8C425C"},
            {"0xFFAA2224", "GetContMovieJpeg_Inner_FFAA2224"},
            {"0xFF8C1FE4", "PipelineFrameCallback_FF8C1FE4"},
            {"0xFF8C3C64", "EVFSetup_FF8C3C64"},
            {"0xFF8C3D38", "StartMjpegInner_FF8C3D38"},
        };

        FunctionManager fm = currentProgram.getFunctionManager();

        for (String[] t : targets) {
            Address addr = currentProgram.getAddressFactory().getAddress(t[0]);
            Function func = fm.getFunctionAt(addr);
            if (func == null) {
                func = fm.getFunctionContaining(addr);
            }

            out.println("========================================");
            out.println("Function: " + t[1]);
            out.println("Address:  " + t[0]);

            if (func == null) {
                out.println("ERROR: No function found at this address");
                out.println();
                continue;
            }

            out.println("Size:     " + func.getBody().getNumAddresses() + " bytes");
            out.println("========================================");

            DecompileResults res = decomp.decompileFunction(func, 120, monitor);
            if (res.decompileCompleted()) {
                out.println(res.getDecompiledFunction().getC());
            } else {
                out.println("DECOMPILATION FAILED: " + res.getErrorMessage());
            }
            out.println();
        }

        decomp.dispose();
        out.close();
        println("Output written to: " + outPath);
    }
}
