#include "SigScanner.h"
#include <iostream>
#include <iomanip>

int main() {
    using namespace scan;

    std::string proc = "RobloxPlayerBeta.exe";
    std::string mod = "RobloxPlayerBeta.dll";
    std::string pat_str = "65 48 8B 04 25 ?? ?? ?? ?? 48 03 38 48 8D 1D";

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
