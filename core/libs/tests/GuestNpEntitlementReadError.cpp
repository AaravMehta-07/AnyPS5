#include "SceTypes.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

extern "C" int APS5_VABI sceNpEntitlementAccessGetAddcontEntitlementInfoList(
    std::uint32_t, NpEntitlementAccessAddcontEntitlementInfo*, std::uint32_t, std::uint32_t*);

int main() {
    const auto path = std::filesystem::temp_directory_path() /
        ("anyps5-entitlement-read-error-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    if (!std::filesystem::create_directory(path)) return 1;
    if (setenv("ANYPS5_ENTITLEMENTS", path.c_str(), 1) != 0) return 1;

    const std::string expectedError = "NpEntitlementAccess: cannot read " + path.string();
    for (int attempt = 0; attempt < 2; ++attempt) {
        std::uint32_t hitNum = 0xA5A5A5A5;
        bool threw = false;
        try {
            sceNpEntitlementAccessGetAddcontEntitlementInfoList(0, nullptr, 0, &hitNum);
        } catch (const std::runtime_error& error) {
            threw = true;
            if (error.what() != expectedError) {
                std::fprintf(stderr, "an entitlement stream read error reported the wrong message\n");
                std::filesystem::remove(path);
                return 1;
            }
        }
        if (!threw) {
            std::fprintf(stderr, "an entitlement stream read error did not throw\n");
            std::filesystem::remove(path);
            return 1;
        }
        if (hitNum != 0xA5A5A5A5) {
            std::fprintf(stderr, "an entitlement stream read error modified hit_num\n");
            std::filesystem::remove(path);
            return 1;
        }
    }

    std::filesystem::remove(path);

    std::ofstream file(path);
    file << "OWNEDADDON000001\nSECONDADDON0001";
    file.close();
    if (!file) return 1;

    std::array<NpEntitlementAccessAddcontEntitlementInfo, 2> addons{};
    std::uint32_t hitNum = 0xA5A5A5A5;
    if (sceNpEntitlementAccessGetAddcontEntitlementInfoList(0, addons.data(), addons.size(), &hitNum) != 0 ||
        hitNum != 2 || std::memcmp(addons[0].entitlement_label.data, "OWNEDADDON000001", 16) != 0 ||
        std::memcmp(addons[1].entitlement_label.data, "SECONDADDON0001", 15) != 0 ||
        addons[0].package_type != 3 || addons[0].download_status != 4 ||
        addons[1].package_type != 3 || addons[1].download_status != 4) {
        std::fprintf(stderr, "the entitlement cache did not retry after a stream read error\n");
        std::filesystem::remove(path);
        return 1;
    }
    std::filesystem::remove(path);
    return 0;
}
