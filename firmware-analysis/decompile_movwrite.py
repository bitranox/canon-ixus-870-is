# Ghidra Python script: Decompile task_MovWrite and related functions
# Run headlessly:
#   analyzeHeadless C:\projects\ixus870IS\firmware-analysis\ghidra_project ixus870_101a
#     -process -noanalysis -scriptPath C:\projects\ixus870IS\firmware-analysis
#     -postScript decompile_movwrite.py
#
# Or run from Ghidra Script Manager.
# @category Analysis

from ghidra.app.decompiler import DecompInterface
import os

decomp = DecompInterface()
decomp.openProgram(currentProgram)

visited = set()
output = []

def decompile_at(addr_long, depth=0, max_depth=2):
    if depth > max_depth:
        return
    key = "0x%08x" % addr_long
    if key in visited:
        return
    visited.add(key)

    address = toAddr(addr_long)
    fm = currentProgram.getFunctionManager()
    func = fm.getFunctionAt(address)
    if func is None:
        output.append("\n// No function found at %s\n" % key)
        return

    results = decomp.decompileFunction(func, 30, monitor)
    if results is None or not results.decompileCompleted():
        output.append("\n// Failed to decompile %s\n" % key)
        return

    c_code = results.getDecompiledFunction().getC()

    output.append("\n\n" + "=" * 72)
    output.append("Function: %s @ 0x%08X (size=%d bytes)" % (
        func.getName(), addr_long, func.getBody().getNumAddresses()))
    output.append("=" * 72)

    # Show callers
    callers = func.getCallingFunctions(monitor)
    if callers:
        output.append("// Called from:")
        for caller in callers:
            output.append("//   0x%s (%s)" % (caller.getEntryPoint(), caller.getName()))

    output.append("")
    output.append(c_code)

    # Recurse into callees
    if depth < max_depth:
        callees = func.getCalledFunctions(monitor)
        for callee in callees:
            callee_addr = callee.getEntryPoint().getOffset()
            # Skip low-level system functions and very common utilities
            if callee_addr < 0xFF800000:
                continue
            # Skip functions we know well already
            skip = [0xFF9300B4, 0xFF92FE8C, 0xFF8EDBE0, 0xFF8EDC88,
                    0xFF85D98C, 0xFF85D3BC, 0xFF8C3BFC]
            if callee_addr in skip:
                continue
            decompile_at(callee_addr, depth + 1)

# Main targets
targets = [
    0xFF92F1EC,  # task_MovWrite
    0xFF92FCFC,  # FUN_ff92fcfc (flush trigger)
    0xFF92F428,  # task_MovWrite setup (creates queue, task)
]

for t in targets:
    decompile_at(t, 0, 2)

# Write output
out_path = os.path.join(
    os.path.dirname(getSourceFile().getAbsolutePath()),
    "task_movwrite_decompiled.txt"
)
with open(out_path, "w") as f:
    f.write("\n".join(output))

print("Wrote %d lines to %s" % (len(output), out_path))
