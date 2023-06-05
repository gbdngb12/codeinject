# codeinject
This project is a tool for injecting code into ELF and PE files.

## Installation

### Build dependencies
- libelf-dev
- binutils-dev
- C++20

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

## Documentation
[wiki](https://github.com/gbdngb12/codeinject.wiki.git)
