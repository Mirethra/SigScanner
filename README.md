# sigscanner

### overview
fast & optimized sig scanner w/ avx2 + multithreading.

### features
- cross-platform (win/linux)
- avx2/sse & fallback
- multi-threaded (dynamic thread pool)
- pattern parsing + hex wildcard support
- proc + module mem parsing

### usage
```cpp
scan::SigScanner sc("proc.exe", {scan::ScanType::AVX2, 4});
if (!sc.GetProcess().IsValid()) exit(1);
sc.AddModule("mod.dll");
scan::SigPattern pat("48 89 5C 24 08 57 48 83 EC 20");
pat.Prepare();
if (auto r = sc.Scan(pat, "mod.dll")) {
    std::cout << "found @ 0x" << std::hex << r->address << "\n";
}
```

### build
- win: `msvc / clang-cl` w/ `/arch:AVX2`
- linux: `g++ -mavx2 -pthread`

### license
mit.

