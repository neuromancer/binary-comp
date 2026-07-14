//@author binary-comp contributors
//@category Binary Comp
//@menupath Tools.Binary Comp.Export To Compile

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Symbol;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Export Ghidra analysis results in the text format consumed by binary-comp.
 *
 * The primary outputs are:
 *
 *   FUN_XXXXXXXX.disassembled.txt  - Ghidra-style disassembly for comparisons.
 *   FUN_XXXXXXXX.decompiled.txt    - Optional decompiler text used by call checks.
 *
 * The script also writes globals.h and strings.txt helper inventories. Those
 * files are intentionally conservative; reconstructed source remains the
 * authority for declarations and values.
 */
public class ExportToCompile extends GhidraScript {
    private static final int DECOMPILE_TIMEOUT_SECONDS = 30;
    private static final Pattern ADDRESS_SUFFIX =
        Pattern.compile(".*_([0-9A-Fa-f]{6}|[0-9A-Fa-f]{8})$");

    @Override
    public void run() throws Exception {
        File outputDir = outputDirectory();
        ensureDirectory(outputDir);

        Listing listing = currentProgram.getListing();
        FunctionIterator functions = listing.getFunctions(true);

        DecompInterface decompiler = new DecompInterface();
        decompiler.setOptions(new DecompileOptions());
        boolean decompilerReady = decompiler.openProgram(currentProgram);

        int exportedDisassembly = 0;
        int exportedDecompilation = 0;
        int skipped = 0;

        println("Exporting binary-comp Ghidra files to " + outputDir.getAbsolutePath());

        while (functions.hasNext() && !monitor.isCancelled()) {
            Function function = functions.next();
            if (!shouldExport(function)) {
                skipped++;
                continue;
            }

            monitor.setMessage("Exporting " + function.getName());
            writeDisassembly(outputDir, listing, function);
            exportedDisassembly++;

            if (decompilerReady) {
                writeDecompilation(outputDir, decompiler, function);
                exportedDecompilation++;
            }
        }

        exportGlobals(outputDir, listing);
        exportStrings(outputDir, listing);
        decompiler.dispose();

        println("Export complete.");
        println("  disassembly files:  " + exportedDisassembly);
        println("  decompiled files:   " + exportedDecompilation);
        println("  skipped functions:  " + skipped);
    }

    private boolean shouldExport(Function function) {
        return !function.isExternal()
            && function.getBody() != null
            && function.getEntryPoint() != null;
    }

    private File outputDirectory() throws Exception {
        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && args[0] != null && !args[0].trim().isEmpty()) {
            return new File(args[0]);
        }
        return askDirectory("Choose binary-comp export directory", "Export");
    }

    private void writeDisassembly(File outputDir, Listing listing, Function function) throws IOException {
        File outFile = new File(outputDir, fileStem(function) + ".disassembled.txt");
        try (BufferedWriter writer = utf8Writer(outFile)) {
            writer.write("Function: " + function.getName());
            writer.newLine();
            writer.write("Address: " + formatAddress(function.getEntryPoint()));
            writer.newLine();
            writer.newLine();
            writer.write(renderDisassembly(listing, function));
        }
    }

    private String renderDisassembly(Listing listing, Function function) {
        AddressSetView body = function.getBody();
        Set<Long> branchTargets = collectInternalBranchTargets(listing, body);
        Set<Long> labelsWritten = new HashSet<>();

        StringBuilder out = new StringBuilder();
        Address previousMaxAddress = null;

        InstructionIterator instructions = listing.getInstructions(body, true);
        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            Address address = instruction.getAddress();
            long offset = address.getOffset();

            boolean startsNewBodyRange = previousMaxAddress != null
                && !address.equals(previousMaxAddress.next());

            if ((startsNewBodyRange || branchTargets.contains(offset))
                    && labelsWritten.add(offset)
                    && !address.equals(function.getEntryPoint())) {
                out.append("\n");
                out.append(String.format("LAB_%08X:", offset));
                out.append("\n");
            }

            out.append(renderInstruction(instruction, body));
            out.append("\n");
            previousMaxAddress = instruction.getMaxAddress();
        }

        return out.toString();
    }

    private Set<Long> collectInternalBranchTargets(Listing listing, AddressSetView body) {
        Set<Long> targets = new HashSet<>();
        InstructionIterator instructions = listing.getInstructions(body, true);
        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            if (!isJumpMnemonic(instruction.getMnemonicString())) {
                continue;
            }
            for (Address flow : instruction.getFlows()) {
                if (flow != null && body.contains(flow)) {
                    targets.add(flow.getOffset());
                }
            }
        }
        return targets;
    }

    private String renderInstruction(Instruction instruction, AddressSetView body) {
        String mnemonic = instruction.getMnemonicString();
        Address[] flows = instruction.getFlows();

        if (flows != null && flows.length > 0 && flows[0] != null) {
            Address target = flows[0];
            if (isCallMnemonic(mnemonic)) {
                // Only a *direct* call can be rendered as "CALL <target>".  An
                // indirect call (CALL dword ptr [...]) has a computed flow, and
                // once Ghidra resolves it to an imported function that flow
                // points into the EXTERNAL address space, whose offset is a
                // small ordinal-like number.  Printing it ("CALL 0x00000088")
                // throws away the IAT slot the caller actually reads, so fall
                // through and let the operand text speak for itself.
                if (!isIndirectFlow(instruction, target)) {
                    return "CALL " + formatAddress(target);
                }
            } else if (isJumpMnemonic(mnemonic) && body.contains(target)) {
                return String.format("%-8s LAB_%08X", mnemonic.toUpperCase(), target.getOffset());
            }
        }

        return uppercaseMnemonic(instruction.toString());
    }

    private boolean isIndirectFlow(Instruction instruction, Address target) {
        FlowType flow = instruction.getFlowType();
        if (flow != null && flow.isComputed()) {
            return true;
        }
        return target.isExternalAddress() || !target.isMemoryAddress();
    }

    private boolean isCallMnemonic(String mnemonic) {
        return mnemonic != null && mnemonic.equalsIgnoreCase("CALL");
    }

    private boolean isJumpMnemonic(String mnemonic) {
        return mnemonic != null && mnemonic.toUpperCase().startsWith("J");
    }

    private String uppercaseMnemonic(String text) {
        String trimmed = text.trim();
        if (trimmed.isEmpty()) {
            return trimmed;
        }
        int index = 0;
        while (index < trimmed.length() && !Character.isWhitespace(trimmed.charAt(index))) {
            index++;
        }
        String mnemonic = trimmed.substring(0, index).toUpperCase();
        return mnemonic + trimmed.substring(index);
    }

    private void writeDecompilation(File outputDir, DecompInterface decompiler, Function function) throws IOException {
        File outFile = new File(outputDir, fileStem(function) + ".decompiled.txt");
        String text = "// Failed to decompile\n";

        DecompileResults results = decompiler.decompileFunction(function, DECOMPILE_TIMEOUT_SECONDS, monitor);
        if (results != null && results.decompileCompleted() && results.getDecompiledFunction() != null) {
            text = normalizeDecompilerWarnings(results.getDecompiledFunction().getC());
        }

        try (BufferedWriter writer = utf8Writer(outFile)) {
            writer.write("Function: " + function.getName());
            writer.newLine();
            writer.write("Address: " + formatAddress(function.getEntryPoint()));
            writer.newLine();
            writer.newLine();
            writer.write(text);
        }
    }

    private String normalizeDecompilerWarnings(String text) {
        StringBuilder out = new StringBuilder();
        for (String line : text.split("\\R", -1)) {
            String trimmed = line.trim();
            if (trimmed.startsWith("/* WARNING:") || trimmed.startsWith("/* Warning:")) {
                out.append("// ");
                out.append(trimmed.replace("/*", "").replace("*/", "").trim());
                out.append("\n");
            } else {
                out.append(line);
                out.append("\n");
            }
        }
        return out.toString();
    }

    private void exportGlobals(File outputDir, Listing listing) throws IOException {
        File outFile = new File(outputDir, "globals.h");
        try (BufferedWriter writer = utf8Writer(outFile)) {
            writer.write("// Global data inventory exported from Ghidra for binary-comp.");
            writer.newLine();
            writer.write("// Reconstructed source declarations remain the authority.");
            writer.newLine();
            writer.newLine();

            DataIterator dataIter = listing.getDefinedData(true);
            while (dataIter.hasNext() && !monitor.isCancelled()) {
                Data data = dataIter.next();
                Address address = data.getAddress();
                MemoryBlock block = currentProgram.getMemory().getBlock(address);
                if (block == null || block.isExecute() || data.getLength() <= 0) {
                    continue;
                }

                String name = symbolNameWithAddress(data);
                if (data.hasStringValue()) {
                    writer.write(String.format("// %s at %s (string, %d bytes)",
                        name, formatAddress(address), data.getLength()));
                    writer.newLine();
                    continue;
                }

                String kind = binaryCompGlobalKind(data);
                if (kind == null) {
                    continue;
                }

                writer.write(kind + " " + name + " = " + globalInitializer(data, kind) + ";");
                writer.newLine();
            }
        }
    }

    private void exportStrings(File outputDir, Listing listing) throws IOException {
        File outFile = new File(outputDir, "strings.txt");
        try (BufferedWriter writer = utf8Writer(outFile)) {
            DataIterator dataIter = listing.getDefinedData(true);
            while (dataIter.hasNext() && !monitor.isCancelled()) {
                Data data = dataIter.next();
                if (!data.hasStringValue()) {
                    continue;
                }
                writer.write(formatAddress(data.getAddress()) + ": " + quoteString(stringValue(data)));
                writer.newLine();
            }
        }
    }

    private String binaryCompGlobalKind(Data data) {
        if (data.isPointer()) {
            return "pointer";
        }

        String type = data.getDataType().getName().toLowerCase();
        int length = data.getLength();

        if (type.startsWith("undefined")) {
            return sizedKind("undefined", length);
        }
        if (type.equals("byte") || type.equals("char")) {
            return "byte";
        }
        if (type.equals("word") || type.equals("short") || type.equals("ushort")) {
            return "word";
        }
        if (type.equals("dword") || type.equals("int") || type.equals("uint")) {
            return "dword";
        }
        if (length == 1 || length == 2 || length == 4 || length == 8) {
            return sizedKind("undefined", length);
        }
        return null;
    }

    private String sizedKind(String base, int length) {
        if (length == 1 || length == 2 || length == 4 || length == 8) {
            return base + length;
        }
        return null;
    }

    private String globalInitializer(Data data, String kind) {
        try {
            if (kind.equals("pointer") && data.getValue() instanceof Address) {
                return formatAddress((Address)data.getValue());
            }
            int bytes = kind.equals("byte") ? 1
                : kind.equals("word") ? 2
                : kind.equals("dword") || kind.equals("pointer") ? 4
                : data.getLength();
            long value = readLittleEndian(data.getAddress(), Math.min(bytes, 8));
            return String.format("0x%X", value);
        } catch (Exception e) {
            return "0";
        }
    }

    private long readLittleEndian(Address address, int length) throws MemoryAccessException {
        byte[] bytes = new byte[length];
        Memory memory = currentProgram.getMemory();
        memory.getBytes(address, bytes);

        long value = 0;
        for (int i = 0; i < bytes.length; i++) {
            value |= ((long)bytes[i] & 0xffL) << (8 * i);
        }
        return value;
    }

    private String symbolNameWithAddress(Data data) {
        Address address = data.getAddress();
        String name = null;
        Symbol primary = currentProgram.getSymbolTable().getPrimarySymbol(address);
        if (primary != null) {
            name = primary.getName();
        }
        if (name == null || name.isEmpty()) {
            name = "DAT";
        }

        name = sanitizeIdentifier(name);
        String hex = String.format("%08X", address.getOffset());
        if (!ADDRESS_SUFFIX.matcher(name).matches()) {
            name = name + "_" + hex;
        }
        return name;
    }

    private String sanitizeIdentifier(String value) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9') || ch == '_') {
                out.append(ch);
            } else {
                out.append('_');
            }
        }
        if (out.length() == 0 || (out.charAt(0) >= '0' && out.charAt(0) <= '9')) {
            out.insert(0, '_');
        }
        return out.toString();
    }

    private String stringValue(Data data) {
        Object value = data.getValue();
        if (value != null) {
            return value.toString();
        }
        return data.getDefaultValueRepresentation();
    }

    private String quoteString(String input) {
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            switch (ch) {
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '"':
                    out.append("\\\"");
                    break;
                case '\0':
                    out.append("\\0");
                    break;
                default:
                    if (ch >= 32 && ch <= 126) {
                        out.append(ch);
                    } else {
                        out.append(String.format("\\x%02X", (int)ch));
                    }
                    break;
            }
        }
        out.append("\"");
        return out.toString();
    }

    private String fileStem(Function function) {
        return String.format("FUN_%08X", function.getEntryPoint().getOffset());
    }

    private String formatAddress(Address address) {
        return String.format("0x%08X", address.getOffset());
    }

    private BufferedWriter utf8Writer(File file) throws IOException {
        return new BufferedWriter(new OutputStreamWriter(
            new FileOutputStream(file), StandardCharsets.UTF_8));
    }

    private void ensureDirectory(File directory) throws IOException {
        if (directory.exists()) {
            if (!directory.isDirectory()) {
                throw new IOException("Export path is not a directory: " + directory);
            }
            return;
        }
        if (!directory.mkdirs()) {
            throw new IOException("Could not create export directory: " + directory);
        }
    }
}
