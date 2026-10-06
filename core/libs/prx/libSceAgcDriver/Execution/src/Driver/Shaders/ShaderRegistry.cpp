#include "prx/libSceAgcDriver/Execution/include/Driver/Driver.hpp"
#include "prx/libSceAgcDriver/Execution/include/Driver/Shaders/ShaderRegistry.hpp"
#include "prx/libSceAgcDriver/Execution/include/Driver/Diagnostics.hpp"
#include "prx/libSceAgcDriver/Execution/include/GuestMemory.hpp"
#include "CacheKey.hpp"
#include "Optimization/ResourceProgram.hpp"
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include "RdnaDecoder/RdnaInstructionDecoder.hpp"
#include "ControlFlow/GraphBuilder.hpp"
#include "ControlFlow/Structurizer.hpp"

namespace AgcDriver::DriverDetail {

std::shared_ptr<const ShaderRecompiler::SourceHandle> SourceHandleFor(const ShaderSnapshot& snapshot, std::size_t codeOffset, std::uint64_t deviceSerial, const ShaderRecompiler::RecompileRequest& request) {
    std::lock_guard lock(snapshot.prepared->mutex);
    for (const auto& entry : snapshot.prepared->entries) {
        if (entry.codeOffset == codeOffset && entry.deviceSerial == deviceSerial && ShaderRecompiler::MatchesPreparedShader(request, *entry.handle)) return entry.handle;
    }
    throw std::runtime_error("AGC driver: prepared shader artifact is missing for the requested static ABI");
}

ShaderRecompiler::RectListShaders PreparedRectangle(const ShaderSnapshot& snapshot, std::uint64_t vertexId, std::uint64_t fragmentId) {
    std::lock_guard lock(snapshot.prepared->mutex);
    for (const auto& entry : snapshot.prepared->rectangles) {
        if (entry.vertexId == vertexId && entry.fragmentId == fragmentId) return entry.shaders;
    }
    throw std::runtime_error("AGC driver: prepared rectangle artifacts are missing");
}

ShaderRecompiler::PreparedShaderInvocation InvocationFor(const ShaderSnapshot& snapshot, std::size_t codeOffset, std::uint64_t deviceSerial, const ShaderRecompiler::RecompileRequest& request) {
    require(codeOffset < snapshot.code.size(), "prepared shader code offset is outside the snapshot");
    const auto code = std::span(snapshot.code).subspan(codeOffset);
    require(request.shader.code.data() == code.data() && request.shader.code.size() == code.size(), "prepared invocation does not refer to registered code");
    auto invocationRequest = request;
    std::lock_guard lock(snapshot.prepared->mutex);
    for (const auto& entry : snapshot.prepared->entries) {
        if (entry.codeOffset != codeOffset || entry.deviceSerial != deviceSerial) continue;
        invocationRequest.shader.code = ShaderRecompiler::GetPreparedCode(*entry.handle);
        if (auto invocation = ShaderRecompiler::PreparedShaderInvocation::TryCreate(invocationRequest, entry.handle)) return std::move(*invocation);
    }
    throw std::runtime_error("AGC driver: prepared shader artifact is missing for the requested static ABI");
}
namespace {

template<typename TValue>
std::vector<TValue> ReadHeaderArray(const ShaderSnapshot& snapshot, const TValue* pointer, std::size_t count) {
    if (count == 0) return {};
    const auto address = reinterpret_cast<std::uintptr_t>(pointer);
    if (address < snapshot.headerAddress || address - snapshot.headerAddress > snapshot.header.size()) throw std::runtime_error("AGC driver: shader metadata is outside the registered header");
    const auto offset = static_cast<std::size_t>(address - snapshot.headerAddress);
    if (count > (snapshot.header.size() - offset) / sizeof(TValue)) throw std::runtime_error("AGC driver: truncated shader metadata");
    std::vector<TValue> result(count);
    std::memcpy(result.data(), snapshot.header.data() + offset, count * sizeof(TValue));
    return result;
}

Shader ReadHeader(const ShaderSnapshot& snapshot) {
    Shader header;
    std::memcpy(&header, snapshot.header.data(), sizeof(header));
    return header;
}

QueueState RegisteredState(const ShaderSnapshot& snapshot) {
    const auto header = ReadHeader(snapshot);
    QueueState state{};
    for (const auto reg : ReadHeaderArray(snapshot, header.sh_registers, header.num_sh_registers)) {
        state.shader.insert_or_assign(reg.offset, reg.value);
    }
    for (const auto reg : ReadHeaderArray(snapshot, header.cx_registers, header.num_cx_registers)) {
        state.context.insert_or_assign(reg.offset, reg.value);
    }
    if (header.specials != nullptr) {
        const auto special = ReadHeaderArray(snapshot, header.specials, 1).front();
        state.context[special.vgt_shader_stages_en.offset] = special.vgt_shader_stages_en.value;
        state.context[special.vgt_gs_out_prim_type.offset] = special.vgt_gs_out_prim_type.value;
        state.userConfig[special.ge_cntl.offset] = special.ge_cntl.value;
        state.userConfig[special.ge_user_vgpr_en.offset] = special.ge_user_vgpr_en.value;
    }
    return state;
}

std::uint32_t RegisterValue(const Registers& registers, std::uint32_t offset) {
    const auto found = registers.find(offset);
    if (found == registers.end()) throw std::runtime_error("AGC driver: missing static shader ABI register " + std::to_string(offset));
    return found->second;
}

std::vector<PreparedShaders::Entry> PrepareRegistered(const ShaderSnapshot& snapshot, const VulkanDevice& device, const QueueState& state, bool registration) {
    using Stage = ShaderRecompiler::ShaderStage;
    const auto header = ReadHeader(snapshot);
    std::uint32_t programRegister;
    std::uint32_t resourceRegister;
    std::uint32_t firstUser = 0;
    Stage stage;
    switch (snapshot.type) {
    case 0: stage = Stage::Compute; programRegister = 0x20c; resourceRegister = 0x213; break;
    case 1: stage = Stage::Fragment; programRegister = 0x008; resourceRegister = 0x00b; break;
    case 2: stage = Stage::Vertex; programRegister = 0x0c8; resourceRegister = 0x08b; firstUser = 8; break;
    case 4: stage = Stage::Mesh; programRegister = 0x0c8; resourceRegister = 0x08b; break;
    case 5: stage = Stage::Local; programRegister = 0x148; resourceRegister = 0x10b; firstUser = 8; break;
    case 6: stage = Stage::Mesh; programRegister = 0x088; resourceRegister = 0x08b; break;
    case 7: stage = Stage::TessellationControl; programRegister = 0x108; resourceRegister = 0x10b; break;
    default: throw std::runtime_error("AGC driver: unsupported registered shader type");
    }
    const auto high = RegisterValue(state.shader, programRegister + 1);
    if ((high & ~0xffu) != 0) throw std::runtime_error("AGC driver: invalid registered program address");
    const auto address = (static_cast<std::uint64_t>(RegisterValue(state.shader, programRegister)) << 8u) | (static_cast<std::uint64_t>(high) << 40u);
    if (address < snapshot.codeAddress || address - snapshot.codeAddress >= snapshot.code.size() * 4u) throw std::runtime_error("AGC driver: registered entry point is outside shader code");
    const auto codeOffset = static_cast<std::size_t>((address - snapshot.codeAddress) / 4u);
    const auto code = std::span(snapshot.code).subspan(codeOffset);
    const auto decoded = ShaderRecompiler::RdnaInstructionDecoder{}.Decode(code);
    auto graph = ShaderRecompiler::GraphBuilder{}.Build(decoded);
    ShaderRecompiler::Structurizer{}.Structurize(graph);
    std::optional<ShaderRecompiler::ShaderComputeStageInfo> compute;
    std::optional<ShaderRecompiler::ShaderPixelStageInfo> pixel;
    std::optional<ShaderRecompiler::ShaderVertexStageInfo> vertex;
    std::optional<ShaderRecompiler::GraphicsCompileContext> graphics;
    std::uint32_t wave;
    const auto resources = RegisterValue(state.shader, resourceRegister);
    auto userCount = (resources >> 1u) & 0x1fu;
    if (stage != Stage::Compute) userCount |= ((resources >> 27u) & 1u) << 5u;
    if (userCount > 32) throw std::runtime_error("AGC driver: static user SGPR count exceeds the register bank");
    if (stage == Stage::Compute) {
        compute = Graphics::DecodeComputeStageInfo(state.shader);
        const auto special = ReadHeaderArray(snapshot, header.specials, 1).front();
        wave = (special.dispatch_modifier & 0x8000u) != 0 ? 32u : 64u;
    } else if (stage == Stage::Fragment) {
        const auto count = RegisterValue(state.context, 0x1b6) & 0x3fu;
        if (registration && count != 0) return {};
        std::array<std::uint8_t, 8> mappings;
        mappings.fill(0xe4u);
        pixel = Graphics::DecodePixelStageInfo(state.context, mappings);
        wave = pixel->wave32 ? 32u : 64u;
    } else {
        const auto routing = RegisterValue(state.context, 0x2d5);
        wave = (routing & 0x00400000u) != 0 ? 32u : 64u;
        if ((routing & 0x20u) != 0 || stage == Stage::Mesh || (routing & 4u) != 0) {
            if (registration) return {};
            auto stageState = state;
            stageState.context[0x1b6] = 0;
            const auto stages = Graphics::DecodeShaderStages(stageState);
            graphics = ShaderRecompiler::GraphicsCompileContext{0, {}, stages.mesh, stages.tessellation, {}};
            if (stages.mesh) { stage = Stage::Mesh; firstUser = 0; }
            if (stages.tessellation && snapshot.type == 2) stage = Stage::TessellationEvaluation;
        }
        if (firstUser == 0) userCount += 8;
    }
    std::vector<std::uint32_t> userData(userCount);
    if (stage != Stage::Compute && stage != Stage::Fragment && snapshot.type != 6) vertex = Graphics::DecodeVertexStageInfo(snapshot.header, snapshot.headerAddress, userData, nullptr, true);
    const std::array<ShaderRecompiler::MemoryRegion, 2> memory{{{snapshot.codeAddress, std::as_bytes(std::span(snapshot.code))}, {snapshot.headerAddress, snapshot.header}}};
    ShaderRecompiler::RecompileRequest request{{stage, address, code, snapshot.headerAddress, snapshot.header}, {wave, firstUser, userData, compute, pixel, vertex, memory}, stage == Stage::Compute ? device.ComputeTarget(wave) : device.Target(), {0, 0, 0, 128}, graphics};
    if (graphics && graphics->mesh) request.layout.pushConstantSizeBytes = ShaderRecompiler::MeshDrawPushOffsetBytes;
    std::vector<PreparedShaders::Entry> entries;
    const auto append = [&] { entries.push_back({codeOffset, device.Serial(), ShaderRecompiler::PrepareShader(request)}); };
    append();
    if (compute) {
        request.context.compute->partialThreads = {1, 1, 1};
        append();
    } else if (pixel) {
        request.layout.pushConstantSizeBytes = ShaderRecompiler::MeshDrawPushOffsetBytes;
        append();
    }
    return entries;
}

}

void Driver::ResolveShaderAbi(const Shader* shader, std::span<const ShaderRegister> context, std::span<const ShaderRegister> primitive) {
    CheckFailure();
    GuestMemory::CheckRange(shader, sizeof(Shader), alignof(Shader));
    std::shared_ptr<const ShaderSnapshot> snapshot;
    {
        std::lock_guard lock(mutex);
        const auto address = reinterpret_cast<std::uintptr_t>(const_cast<const void*>(shader->code));
        require(shaders != nullptr && shaders->contains(address), "static ABI refers to an unregistered shader");
        snapshot = shaders->at(address);
        require(snapshot->headerAddress == reinterpret_cast<std::uintptr_t>(shader), "static ABI refers to a replaced shader header");
    }
    auto state = RegisteredState(*snapshot);
    for (const auto reg : context) state.context[reg.offset] = reg.value;
    for (const auto reg : primitive) state.userConfig[reg.offset] = reg.value;
    const auto localDevice = device.Load();
    require(localDevice != nullptr, "shader registration device is missing");
    auto entries = PrepareRegistered(*snapshot, *localDevice, state, false);
    std::lock_guard lock(snapshot->prepared->mutex);
    for (auto& entry : entries) {
        const auto duplicate = std::ranges::any_of(snapshot->prepared->entries, [&](const auto& existing) { return existing.handle->artifact == entry.handle->artifact; });
        if (!duplicate) snapshot->prepared->entries.push_back(std::move(entry));
    }
}

void Driver::ResolveGraphicsAbi(const Shader* vertex, const Shader* pixel, std::uint32_t primitiveType) {
    CheckFailure();
    if (primitiveType != 7 && primitiveType != 17) return;
    require(vertex != nullptr && pixel != nullptr, "rectangle ABI requires vertex and fragment shaders");
    std::shared_ptr<const ShaderSnapshot> front;
    std::shared_ptr<const ShaderSnapshot> fragment;
    {
        std::lock_guard lock(mutex);
        front = shaders->at(reinterpret_cast<std::uintptr_t>(const_cast<const void*>(vertex->code)));
        fragment = shaders->at(reinterpret_cast<std::uintptr_t>(const_cast<const void*>(pixel->code)));
    }
    require(front != fragment, "rectangle stages refer to the same shader");
    const auto localDevice = device.Load();
    require(localDevice != nullptr, "shader registration device is missing");
    std::scoped_lock lock(front->prepared->mutex, fragment->prepared->mutex);
    std::vector<PreparedShaders::Rectangle> rectangles;
    for (const auto& vertexEntry : front->prepared->entries) {
        for (const auto& fragmentEntry : fragment->prepared->entries) {
            const auto& vertexArtifact = ShaderRecompiler::GetPreparedArtifact(*vertexEntry.handle);
            const auto& fragmentArtifact = ShaderRecompiler::GetPreparedArtifact(*fragmentEntry.handle);
            ShaderRecompiler::RecompileResult vertexResult;
            ShaderRecompiler::RecompileResult fragmentResult;
            static_cast<ShaderRecompiler::CompiledShaderArtifact&>(vertexResult) = vertexArtifact;
            static_cast<ShaderRecompiler::CompiledShaderArtifact&>(fragmentResult) = fragmentArtifact;
            rectangles.push_back({vertexArtifact.variantId, fragmentArtifact.variantId, ShaderRecompiler::BuildRectListShaders(vertexResult, fragmentResult, localDevice->Target())});
        }
    }
    require(!rectangles.empty(), "rectangle ABI has missing stage artifacts");
    front->prepared->rectangles.insert(front->prepared->rectangles.end(), std::make_move_iterator(rectangles.begin()), std::make_move_iterator(rectangles.end()));
}
void Driver::RegisterShader(const Shader* shader) {
    CheckFailure();
    GuestMemory::CheckRange(shader, sizeof(Shader), alignof(Shader));
    require(shader->file_header == 0x34333231u && shader->version == 0x18u, "invalid shader header");
    require(shader->header_size >= sizeof(Shader), "shader header is smaller than its fixed fields");
    require(shader->shader_size != 0 && (shader->shader_size & 3u) == 0, "invalid shader size");
    GuestMemory::CheckRange(shader, shader->header_size, alignof(Shader));
    const auto* code = const_cast<const void*>(shader->code);
    GuestMemory::CheckRange(code, shader->shader_size, 256);
    ShaderSnapshot snapshot{reinterpret_cast<std::uintptr_t>(code), reinterpret_cast<std::uintptr_t>(shader), shader->type, {}, {}};
    snapshot.code.resize(shader->shader_size / sizeof(std::uint32_t));
    std::memcpy(snapshot.code.data(), code, shader->shader_size);
    snapshot.header.resize(shader->header_size);
    std::memcpy(snapshot.header.data(), shader, shader->header_size);

    std::shared_ptr<VulkanDevice> localDevice = device.Load();
    if (localDevice == nullptr) {
        std::lock_guard gpuLock(GuestMemory::GpuMutex());
        if (device == nullptr) device = std::make_shared<VulkanDevice>();
        localDevice = device;
    }
    snapshot.prepared->entries = PrepareRegistered(snapshot, *localDevice, RegisteredState(snapshot), true);
    static const char* traceRegs = std::getenv("APS5_TRACE_SHADER_REGS");
    if (traceRegs != nullptr && (std::string(traceRegs) == "all" || std::strtoull(traceRegs, nullptr, 16) == snapshot.codeAddress)) {
        std::fprintf(stderr, "[shader] 0x%llx type %u cx", static_cast<unsigned long long>(snapshot.codeAddress), shader->type);
        for (std::uint32_t i = 0; i < shader->num_cx_registers && shader->cx_registers != nullptr; ++i) std::fprintf(stderr, " %x=%08x", shader->cx_registers[i].offset, shader->cx_registers[i].value);
        std::fprintf(stderr, " sh");
        for (std::uint32_t i = 0; i < shader->num_sh_registers && shader->sh_registers != nullptr; ++i) std::fprintf(stderr, " %x=%08x", shader->sh_registers[i].offset, shader->sh_registers[i].value);
        std::fprintf(stderr, "\n");
    }
    std::lock_guard lock(mutex);
    rethrowFailure();
    const auto address = snapshot.codeAddress;

    if (shaders == nullptr) shaders = std::make_shared<ShaderRegistry>();
    else if (shaders.use_count() != 1) shaders = std::make_shared<ShaderRegistry>(*shaders);
    shaders->insert_or_assign(address, std::make_shared<const ShaderSnapshot>(std::move(snapshot)));
}

}
