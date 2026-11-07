#pragma once

#include <cstddef>
#include <cstdint>

namespace passwall::native {

// Limite commune du payload JSON Native Messaging. Le préfixe little-endian
// de quatre octets qui transporte la longueur n'est pas compris dans cette
// valeur.
inline constexpr std::uint32_t NativeMessageMaxPayloadBytes = 1024U * 1024U;
inline constexpr std::size_t NativeMessageFrameHeaderBytes =
    sizeof(std::uint32_t);

} // namespace passwall::native
