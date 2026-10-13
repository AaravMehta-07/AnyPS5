#include "SceTypes.hpp"
#include "prx/libkernel/AppMetadata/include/AppMetadata.hpp"

#include <array>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

extern "C" int APS5_VABI getpid_nid_postfix(void);

static void Require(bool value) { if (!value) std::abort(); }

static constexpr std::array<std::uint8_t, 68> ValidIcon = {
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
    0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x04, 0x00, 0x00, 0x00, 0xB5, 0x1C, 0x0C, 0x02, 0x00, 0x00, 0x00,
    0x0B, 0x49, 0x44, 0x41, 0x54, 0x78, 0xDA, 0x63, 0xFC, 0xFF, 0x1F, 0x00,
    0x03, 0x03, 0x02, 0x00, 0xEF, 0xBF, 0x9F, 0xDB, 0x00, 0x00, 0x00, 0x00,
    0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
};

static void WriteIcon(std::string_view bytes) {
    std::filesystem::create_directories("app0/sce_sys");
    std::ofstream file("app0/sce_sys/icon0.png", std::ios::binary);
    if (!file.is_open()) throw std::runtime_error("failed to create icon fixture");
    file.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (!file) throw std::runtime_error("failed to write icon fixture");
}

static bool HasError(std::string_view expected, bool availability = false) {
    try {
        if (availability) HasAppIcon_nid_postfix();
        else GetAppIconData_nid_postfix();
    } catch (const std::runtime_error& error) {
        return error.what() == expected;
    }
    return false;
}

int main(int argc, char** argv) {
    Require(argc == 2);
    const std::string_view mode = argv[1];
    Require(mode == "missing" || mode == "valid" || mode == "invalid");

    const auto previous = std::filesystem::current_path();
    const auto root = std::filesystem::temp_directory_path() /
        ("guest_app_icon_" + std::to_string(getpid_nid_postfix()) + "_" + std::string(mode));
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    std::filesystem::current_path(root);

    if (mode == "missing") {
        Require(!HasAppIcon_nid_postfix());
        Require(!HasAppIcon_nid_postfix());
        Require(HasError("icon not available"));
        Require(HasError("icon not available"));
    } else if (mode == "valid") {
        WriteIcon(std::string_view(reinterpret_cast<const char*>(ValidIcon.data()), ValidIcon.size()));
        std::array<std::thread, 16> threads;
        std::array<bool, 16> loaded{};
        for (std::size_t index = 0; index < threads.size(); ++index) {
            threads[index] = std::thread([&, index] {
                try {
                    const auto icon = GetAppIconData_nid_postfix();
                    loaded[index] = icon.bytes != nullptr && icon.size == ValidIcon.size()
                        && std::memcmp(icon.bytes, ValidIcon.data(), ValidIcon.size()) == 0;
                } catch (...) {
                    loaded[index] = false;
                }
            });
        }
        for (auto& thread : threads) thread.join();
        for (const bool result : loaded) Require(result);
        Require(HasAppIcon_nid_postfix());
        const auto icon = GetAppIconData_nid_postfix();
        Require(icon.bytes != nullptr && icon.size == ValidIcon.size());
        Require(std::memcmp(icon.bytes, ValidIcon.data(), ValidIcon.size()) == 0);
        const auto cached = GetAppIconData_nid_postfix();
        Require(cached.bytes == icon.bytes && cached.size == icon.size);
    } else {
        WriteIcon("not a PNG");
        for (int attempt = 0; attempt < 2; ++attempt)
            Require(HasError("icon0.png is not a valid PNG file", true));
        Require(HasError("icon0.png is not a valid PNG file"));
        WriteIcon(std::string_view(reinterpret_cast<const char*>(ValidIcon.data()), ValidIcon.size()));
        Require(HasAppIcon_nid_postfix());
        const auto icon = GetAppIconData_nid_postfix();
        Require(icon.size == ValidIcon.size());
        Require(std::memcmp(icon.bytes, ValidIcon.data(), ValidIcon.size()) == 0);
    }

    std::filesystem::current_path(previous);
    std::filesystem::remove_all(root);
}
