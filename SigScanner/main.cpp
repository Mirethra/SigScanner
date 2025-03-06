#include "SigScanner.h"
#include <iostream>
#include <iomanip>

#include <Windows.h>
#include <TlHelp32.h>


int main() {
    using namespace scan;

    std::string proc = "anything.exe"; // Not being used in this example yet.
    std::string mod = "USER32.dll";
    std::string pat_str = "48 89 5C 24 08 57 48 83 EC 20 48 8B 05"; // GetWindowRect

    ScanOptions opts{ ScanType::AVX2, 4 };
    SigScanner sc(proc, opts);

    if (!sc.GetProcess().IsValid()) {
        std::cerr << "fail: attach " << proc << "\n";
        return 1;
    }

    std::cout << "ok: attached " << proc << " pid=" << sc.GetProcess().GetPID() << "\n";

    if (!sc.AddModule(mod)) {
        std::cerr << "fail: add mod " << mod << "\n";
        return 1;
    }

    std::cout << "ok: added " << mod << "\n";

    SigPattern pat(pat_str);
    pat.Prepare();

    auto r = sc.Scan(pat, mod);
    if (r) {
        std::cout << "found @ 0x" << std::hex << r->address << "\n";
        std::cout << "res @ 0x" << std::hex << r->ResolveRelative(5) << "\n";
    }
    else {
        std::cout << "not found\n";
    }

    auto rs = sc.ScanAll(pat, mod);
    std::cout << "hits: " << rs.size() << "\n";

    for (const auto& res : rs) {
        std::cout << "hit @ 0x" << std::hex << res.address << "\n";
    }

    return 0;
}
