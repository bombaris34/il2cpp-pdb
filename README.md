# Il2CppDumper

[![Build status](https://ci.appveyor.com/api/projects/status/anhqw33vcpmp8ofa?svg=true)](https://ci.appveyor.com/project/Perfare/il2cppdumper/branch/master/artifacts)

中文说明请戳[这里](README.zh-CN.md)

Unity il2cpp reverse engineer

## Features

* Complete DLL restore (except code), can be used to extract `MonoBehaviour` and `MonoScript`
* Supports ELF, ELF64, Mach-O, PE, NSO and WASM format
* Supports Unity 5.3 - 2022.2
* Supports generate IDA, Ghidra and Binary Ninja scripts to help them better analyze il2cpp files
* Supports generate structures header file
* Supports Android memory dumped `libil2cpp.so` file to bypass protection
* Support bypassing simple PE protection
* **Native debug symbols for x64 PE (PDB) and 64-bit Mach-O (dSYM)** — see below

## Native debug symbol generation (this fork)

[`il2cpp_pdbgen`](il2cpp_pdbgen/) is a standalone Rust tool that converts
Il2CppDumper's `il2cpp.h` and `script.json` into a Windows PDB or Mach-O
DWARF dSYM. It does not require a compiler or linker to generate symbols.

The generated `GameAssembly.pdb` contains:

* **Function names + boundaries** for every method (publics + globals)
* **Full struct/union types** from `il2cpp.h` with correct x64 layouts
* **Typed function prototypes** (each function wired to its signature)
* A GUID/age matching the binary's debug directory, so IDA **auto-loads** it

For 64-bit Mach-O (x86-64 and ARM64), the generator emits a UUID-matched dSYM
with function ranges, struct and union layouts, and prototypes reconstructed
from the same input. It does not generate source code or line information.
Types and function boundaries are inferred from the dumper's output.
Nested anonymous structs and unions retain their layout, and function-pointer
fields retain their return types, parameters, and supported `const` / `volatile`
qualifiers. Other declarations are still reconstructed from the generated
header rather than original compiler debug information.
In a Linux LLDB smoke test, name-based breakpoints resolved but address lookup
displayed the original unnamed Mach-O symbol instead of the DWARF name;
`llvm-symbolizer` resolved the generated name. Consumer behavior may differ.

### Setup

```powershell
# Build the tool and place it next to Il2CppDumper's output.
# Add -InstallRust to install Rust automatically if you don't have it.
.\setup.ps1            # or:  .\setup.ps1 -InstallRust
```

On Linux or macOS, run `cargo build --release --manifest-path il2cpp_pdbgen/Cargo.toml`
and copy `il2cpp_pdbgen/target/release/il2cpp_pdbgen` next to the built
Il2CppDumper executable, or set `IL2CPP_PDBGEN` to its absolute path.

Once built, Il2CppDumper automatically generates a `.pdb` for x64 PE or a
`<binary>.dSYM` bundle for 64-bit Mach-O next to the selected binary. Set
`"GeneratePdb": false` in `config.json` to disable both. For a universal
Mach-O, the dSYM corresponds to the architecture selected in the dumper.
The generator refuses to overwrite an existing dSYM bundle.

You can also run it manually:

```
il2cpp_pdbgen <dir>                                   # dir with GameAssembly.dll, il2cpp.h, script.json
il2cpp_pdbgen <binary> <il2cpp.h> <script.json> [output] [--slice <index>]
```

For a universal Mach-O, `--slice` is the zero-based architecture index and
must match the slice used to produce `script.json` and `il2cpp.h`. The default
Mach-O output is `<binary>.dSYM`; an explicit output is a new bundle directory.
For example, pass `--slice 0` for the first architecture.

Then open the binary in IDA — the `.pdb` beside it is picked up automatically.

## Usage

Run `Il2CppDumper.exe` and choose the il2cpp executable file and `global-metadata.dat` file, then enter the information as prompted

The program will then generate all the output files in current working directory

### Command-line

```
Il2CppDumper.exe <executable-file> <global-metadata> <output-directory>
```

### Outputs

#### DummyDll

Folder, containing all restored dll files

Use [dnSpy](https://github.com/0xd4d/dnSpy), [ILSpy](https://github.com/icsharpcode/ILSpy) or other .Net decompiler tools to view

Can be used to extract Unity `MonoBehaviour` and `MonoScript`, for [UtinyRipper](https://github.com/mafaca/UtinyRipper), [UABE](https://7daystodie.com/forums/showthread.php?22675-Unity-Assets-Bundle-Extractor)

#### ida.py

For IDA

#### ida_with_struct.py

For IDA, read il2cpp.h file and apply structure information in IDA

#### il2cpp.h

structure information header file

#### ghidra.py

For Ghidra

#### Il2CppBinaryNinja

For BinaryNinja

#### ghidra_wasm.py

For Ghidra, work with [ghidra-wasm-plugin](https://github.com/nneonneo/ghidra-wasm-plugin)

#### script.json

For ida.py, ghidra.py and Il2CppBinaryNinja

#### stringliteral.json

Contains all stringLiteral information

### Configuration

All the configuration options are located in `config.json`

Available options:

* `DumpMethod`, `DumpField`, `DumpProperty`, `DumpAttribute`, `DumpFieldOffset`, `DumpMethodOffset`, `DumpTypeDefIndex`
  * Whether to output these information to dump.cs

* `GenerateDummyDll`, `GenerateScript`
  * Whether to generate these things

* `DummyDllAddToken`
  * Whether to add token in DummyDll

* `RequireAnyKey`
  * Whether to press any key to exit at the end

* `ForceIl2CppVersion`, `ForceVersion`
  * If `ForceIl2CppVersion` is `true`, the program will use the version number specified in `ForceVersion` to choose parser for il2cpp binaries (does not affect the choice of metadata parser). This may be useful on some older il2cpp version (e.g. the program may need to use v16 parser on il2cpp v20 (Android) binaries in order to work properly)

* `ForceDump`
  * Force files to be treated as dumped

* `NoRedirectedPointer`
  * Treat pointers in dumped files as unredirected, This option needs to be `true` for files dumped from some devices

## Common errors

#### `ERROR: Metadata file supplied is not valid metadata file.`  

Make sure you choose the correct file. Sometimes games may obfuscate this file for content protection purposes and so on. Deobfuscating of such files is beyond the scope of this program, so please **DO NOT** file an issue regarding to deobfuscating.

If your file is `libil2cpp.so` and you have a rooted Android phone, you can try my other project [Zygisk-Il2CppDumper](https://github.com/Perfare/Zygisk-Il2CppDumper), it can bypass this protection.

#### `ERROR: Can't use auto mode to process file, try manual mode.`

Please note that the executable file for the PC platform is `GameAssembly.dll` or `*Assembly.dll`

You can open a new issue and upload the file, I will try to solve.

#### `ERROR: This file may be protected.`

Il2CppDumper detected that the executable file has been protected, use `GameGuardian` to dump `libil2cpp.so` from the game memory, then use Il2CppDumper to load and follow the prompts, can bypass most protections.

If you have a rooted Android phone, you can try my other project [Zygisk-Il2CppDumper](https://github.com/Perfare/Zygisk-Il2CppDumper), it can bypass almost all protections.

## Credits

- Jumboperson - [Il2CppDumper](https://github.com/Jumboperson/Il2CppDumper)
