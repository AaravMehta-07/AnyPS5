#include "prx/libSceAgc/Shader/include/InterpolantMapping.hpp"

#include <cstdio>
#include <array>
#include <algorithm>
#include <stdexcept>
#include <prx/libc/include/General.hpp>

#include "SceShaders.hpp"
#include "prx/libSceAgcDriver/Execution/include/ShaderPreparationScope.hpp"
#include "prx/libSceAgcDriver/Execution/include/Driver.hpp"
#include "prx/libSceAgc/Shader/include/ShaderUtils.hpp"
#include "prx/libSceAgc/Shader/include/ShaderConstants.hpp"

extern "C" {

APS5_EXPORT("HV4j+E0MBHE", sceAgcCreateInterpolantMapping);
int APS5_VABI sceAgcCreateInterpolantMapping(ShaderRegister* regs, const Shader* gs, const Shader* ps) {
    constexpr auto fn = __func__;
    if (regs == nullptr) {
        throw std::runtime_error(std::string(fn) + ": regs is null");
    }
    if (ps != nullptr && ps->num_input_semantics > 32) {
        throw std::runtime_error(std::string(fn) + ": input semantic count exceeds 32");
    }

    AgcDriver::ShaderPreparationScope transaction;
    std::array<ShaderRegister, 32> values{};
    auto* output = regs;
    regs = values.data();
    if (ps == nullptr || ps->num_input_semantics == 0) {
        FillIdentityInterpolants(regs, 0);
        if (ps != nullptr) {
            AgcDriverResolveShaderAbi_nid_postfix(ps, {regs, 32}, {});
            if (gs != nullptr) AgcDriverResolveGraphicsAbi_nid_postfix(gs, ps, 0);
        }
        transaction.Commit();
        std::copy(values.begin(), values.end(), output);
        return 0;
    }

    if (ps->num_input_semantics != 0 && ps->input_semantics == nullptr) {
        throw std::runtime_error(std::string(fn) + ": ps->input_semantics is null but num_input_semantics != 0");
    }

    if (gs == nullptr) {
        throw std::runtime_error(std::string(fn) + ": gs is null");
    }

    if (gs->num_output_semantics != 0 && gs->output_semantics == nullptr) {
        throw std::runtime_error(std::string(fn) + ": gs->output_semantics is null but num_output_semantics != 0");
    }

    for (std::uint32_t i = 0; i < ps->num_input_semantics; ++i) {
        const ShaderSemantic& psSemantic = ps->input_semantics[i];
        const ShaderSemantic* gsSemantic = FindOutputSemantic(gs, psSemantic.semantic);
        const std::uint32_t psWord = ShaderSemanticWord(psSemantic);

        std::uint32_t value = ((psWord & 0x00300000u) != 0)
            ? CreateInterpolantF16Value(psWord, gsSemantic)
            : CreateInterpolantNonF16Value(psWord, gsSemantic);

        value = (gsSemantic == nullptr)
            ? CreateInterpolantDefaultValue(value, psWord)
            : CreateInterpolantMappingValue(value, psWord, ShaderSemanticWord(*gsSemantic));

        SetInterpolantRegister(regs, i, value);
    }

    FillIdentityInterpolants(regs, ps->num_input_semantics);
    AgcDriverResolveShaderAbi_nid_postfix(ps, {regs, 32}, {});
    AgcDriverResolveGraphicsAbi_nid_postfix(gs, ps, 0);
    transaction.Commit();
    std::copy(values.begin(), values.end(), output);
    return 0;
}

}
