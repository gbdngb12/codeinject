# codeinject
This project is a tool for injecting code into ELF and PE files.

## Installation

### Build dependencies
- libelf-dev
- binutils-dev
- C++20(libfmt-dev)

### Build

```bash
$ ./configure.sh
$ ./build.sh
```

## Usage

```bash
$ cd build/
$ ./codeinject <target> <inject> <address>
```

### PE32
```bash
$ ./codeinject pe_32.exe pe_32_backdoor.bin
pe inject code
```

### PE64
```bash
$ ./codeinject pe_64.exe pe_64_backdoor.bin
pe inject code
```

### ELF32
```bash
$ ./codeinject elf_32 elf_32_backdoor.bin
elf inject code
```

### ELF64
```bash
$ ./codeinject elf_64 elf_64_backdoor.bin
elf inject code
```

## Documentation
[wiki](https://github.com/gbdngb12/codeinject/wiki)
