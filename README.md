# cvm_tool: CRI ROFS Decryptor by roxfan (modified by JayFoxRox)

## Build

```
mkdir build
cd build
cmake ..
make
```

## Run

Run `./cvm_tool` to see the help:

```
ROFS tool (git version).
Usage: cvm_tool [options] <command> <file1>...
    available commands:
    info  [-p <password>] <file.cvm>                          Show information about a ROFS volume
    split [-p <password>] <file.cvm> <file.iso> [<file.hdr>]  Extract ISO file from a ROFS volume
    mkcvm [-p <password>] <file.cvm> <file.iso>  <file.hdr>   Make a ROFS volume from an ISO file and header file
```

## License

- Contributions by roxfan have not been given a specific license (assume "All Rights Reserved").
- Contributions by JayFoxRox are licensed as CC0.

