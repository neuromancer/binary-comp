from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest


STUBS = {
    "ghidra/app/script/GhidraScript.java": """
        package ghidra.app.script;

        import java.io.File;
        import ghidra.program.model.listing.Program;
        import ghidra.util.task.TaskMonitor;

        public class GhidraScript {
            protected Program currentProgram;
            protected TaskMonitor monitor;

            public void run() throws Exception {
            }

            protected File askDirectory(String title, String approveButtonText) {
                return new File(".");
            }

            protected String[] getScriptArgs() {
                return new String[0];
            }

            protected void println(String message) {
            }
        }
    """,
    "ghidra/app/decompiler/DecompInterface.java": """
        package ghidra.app.decompiler;

        import ghidra.program.model.listing.Function;
        import ghidra.program.model.listing.Program;
        import ghidra.util.task.TaskMonitor;

        public class DecompInterface {
            public void setOptions(DecompileOptions options) {
            }

            public boolean openProgram(Program program) {
                return true;
            }

            public DecompileResults decompileFunction(Function function, int timeoutSeconds, TaskMonitor monitor) {
                return new DecompileResults();
            }

            public void dispose() {
            }
        }
    """,
    "ghidra/app/decompiler/DecompileOptions.java": """
        package ghidra.app.decompiler;

        public class DecompileOptions {
        }
    """,
    "ghidra/app/decompiler/DecompileResults.java": """
        package ghidra.app.decompiler;

        public class DecompileResults {
            public boolean decompileCompleted() {
                return true;
            }

            public DecompiledFunction getDecompiledFunction() {
                return new DecompiledFunction();
            }

            public static class DecompiledFunction {
                public String getC() {
                    return "";
                }
            }
        }
    """,
    "ghidra/program/model/address/Address.java": """
        package ghidra.program.model.address;

        public class Address {
            public long getOffset() {
                return 0;
            }

            public Address next() {
                return this;
            }

            public boolean isMemoryAddress() {
                return true;
            }

            public boolean isExternalAddress() {
                return false;
            }
        }
    """,
    "ghidra/program/model/address/AddressSetView.java": """
        package ghidra.program.model.address;

        public interface AddressSetView {
            boolean contains(Address address);
        }
    """,
    "ghidra/program/model/data/DataType.java": """
        package ghidra.program.model.data;

        public class DataType {
            public String getName() {
                return "";
            }
        }
    """,
    "ghidra/program/model/listing/Data.java": """
        package ghidra.program.model.listing;

        import ghidra.program.model.address.Address;
        import ghidra.program.model.data.DataType;

        public class Data {
            public Address getAddress() {
                return new Address();
            }

            public int getLength() {
                return 0;
            }

            public boolean hasStringValue() {
                return false;
            }

            public boolean isPointer() {
                return false;
            }

            public Object getValue() {
                return null;
            }

            public String getDefaultValueRepresentation() {
                return "";
            }

            public DataType getDataType() {
                return new DataType();
            }
        }
    """,
    "ghidra/program/model/listing/DataIterator.java": """
        package ghidra.program.model.listing;

        import java.util.Iterator;

        public interface DataIterator extends Iterator<Data> {
        }
    """,
    "ghidra/program/model/listing/Function.java": """
        package ghidra.program.model.listing;

        import ghidra.program.model.address.Address;
        import ghidra.program.model.address.AddressSetView;

        public class Function {
            public boolean isExternal() {
                return false;
            }

            public AddressSetView getBody() {
                return null;
            }

            public Address getEntryPoint() {
                return new Address();
            }

            public String getName() {
                return "";
            }
        }
    """,
    "ghidra/program/model/listing/FunctionIterator.java": """
        package ghidra.program.model.listing;

        import java.util.Iterator;

        public interface FunctionIterator extends Iterator<Function> {
        }
    """,
    "ghidra/program/model/listing/Instruction.java": """
        package ghidra.program.model.listing;

        import ghidra.program.model.address.Address;

        import ghidra.program.model.symbol.FlowType;

        public class Instruction {
            public String getMnemonicString() {
                return "";
            }

            public Address[] getFlows() {
                return new Address[0];
            }

            public Address getAddress() {
                return new Address();
            }

            public Address getMaxAddress() {
                return new Address();
            }

            public FlowType getFlowType() {
                return new FlowType();
            }
        }
    """,
    "ghidra/program/model/symbol/FlowType.java": """
        package ghidra.program.model.symbol;

        public class FlowType {
            public boolean isComputed() {
                return false;
            }
        }
    """,
    "ghidra/program/model/listing/InstructionIterator.java": """
        package ghidra.program.model.listing;

        import java.util.Iterator;

        public interface InstructionIterator extends Iterator<Instruction> {
        }
    """,
    "ghidra/program/model/listing/Listing.java": """
        package ghidra.program.model.listing;

        import ghidra.program.model.address.AddressSetView;

        public class Listing {
            public FunctionIterator getFunctions(boolean forward) {
                return null;
            }

            public InstructionIterator getInstructions(AddressSetView body, boolean forward) {
                return null;
            }

            public DataIterator getDefinedData(boolean forward) {
                return null;
            }
        }
    """,
    "ghidra/program/model/listing/Program.java": """
        package ghidra.program.model.listing;

        import ghidra.program.model.mem.Memory;
        import ghidra.program.model.symbol.SymbolTable;

        public class Program {
            public Listing getListing() {
                return new Listing();
            }

            public Memory getMemory() {
                return new Memory();
            }

            public SymbolTable getSymbolTable() {
                return new SymbolTable();
            }
        }
    """,
    "ghidra/program/model/mem/Memory.java": """
        package ghidra.program.model.mem;

        import ghidra.program.model.address.Address;

        public class Memory {
            public MemoryBlock getBlock(Address address) {
                return new MemoryBlock();
            }

            public void getBytes(Address address, byte[] bytes) throws MemoryAccessException {
            }
        }
    """,
    "ghidra/program/model/mem/MemoryAccessException.java": """
        package ghidra.program.model.mem;

        public class MemoryAccessException extends Exception {
        }
    """,
    "ghidra/program/model/mem/MemoryBlock.java": """
        package ghidra.program.model.mem;

        public class MemoryBlock {
            public boolean isExecute() {
                return false;
            }
        }
    """,
    "ghidra/program/model/symbol/Symbol.java": """
        package ghidra.program.model.symbol;

        public class Symbol {
            public String getName() {
                return "";
            }
        }
    """,
    "ghidra/program/model/symbol/SymbolTable.java": """
        package ghidra.program.model.symbol;

        import ghidra.program.model.address.Address;

        public class SymbolTable {
            public Symbol getPrimarySymbol(Address address) {
                return null;
            }
        }
    """,
    "ghidra/util/task/TaskMonitor.java": """
        package ghidra.util.task;

        public class TaskMonitor {
            public boolean isCancelled() {
                return false;
            }

            public void setMessage(String message) {
            }
        }
    """,
}


def write_stub(root: Path, relative_path: str, source: str) -> Path:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(source).strip() + "\n", encoding="utf-8")
    return path


def test_export_to_compile_java_compiles_against_basic_ghidra_stubs(tmp_path: Path) -> None:
    javac = shutil.which("javac")
    if javac is None:
        pytest.skip("javac is not installed")

    repo_root = Path(__file__).resolve().parents[1]
    stub_root = tmp_path / "ghidra-stubs"
    class_dir = tmp_path / "classes"

    sources = [write_stub(stub_root, path, source) for path, source in STUBS.items()]
    sources.append(repo_root / "ghidra_scripts" / "ExportToCompile.java")

    result = subprocess.run(
        [javac, "-proc:none", "-d", str(class_dir), *map(str, sources)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
