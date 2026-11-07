#pragma once

#include <sodium.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>


namespace passwall::core {

struct PasswordOptions {
    std::size_t length = 20;
    bool lowercase = true;
    bool uppercase = true;
    bool digits = true;
    bool symbols = true;
};

class PasswordGenerator {
public:
    [[nodiscard]] static bool generate(
        const PasswordOptions& options,
        std::string& output,
        std::string& error)
    {
        output.clear();
        error.clear();

        constexpr std::size_t MinLength = 8;
        constexpr std::size_t MaxLength = 128;

        if (sodium_init() < 0) {
            error = "Impossible d'initialiser le générateur cryptographique.";
            return false;
        }

        if (options.length < MinLength ||
            options.length > MaxLength) {
            error = "La longueur doit être comprise entre 8 et 128 caractères.";
            return false;
        }

        std::vector<std::string> selectedSets;

        if (options.lowercase) {
            selectedSets.emplace_back(
                "abcdefghijkmnopqrstuvwxyz");
        }

        if (options.uppercase) {
            selectedSets.emplace_back(
                "ABCDEFGHJKLMNPQRSTUVWXYZ");
        }

        if (options.digits) {
            selectedSets.emplace_back("23456789");
        }

        if (options.symbols) {
            selectedSets.emplace_back("!@#$%^&*()-_=+[]{}:,.?");
        }

        if (selectedSets.empty()) {
            error = "Sélectionne au moins un type de caractère.";
            return false;
        }

        if (options.length < selectedSets.size()) {
            error = "La longueur est trop courte pour les types sélectionnés.";
            return false;
        }

        std::string allCharacters;
        for (const auto& set : selectedSets) {
            allCharacters += set;
        }

        output.reserve(options.length);

        // Garantit au moins un caractère de chaque type sélectionné.
        for (const auto& set : selectedSets) {
            const auto index = randombytes_uniform(
                static_cast<std::uint32_t>(set.size()));

            output.push_back(set[index]);
        }

        // Complète le mot de passe avec des caractères aléatoires.
        while (output.size() < options.length) {
            const auto index = randombytes_uniform(
                static_cast<std::uint32_t>(allCharacters.size()));

            output.push_back(allCharacters[index]);
        }

        // Mélange les caractères sans biais modulo.
        for (std::size_t i = output.size(); i > 1; --i) {
            const auto j = static_cast<std::size_t>(
                randombytes_uniform(static_cast<std::uint32_t>(i)));

            std::swap(output[i - 1], output[j]);
        }

        return true;
    }
};

} // namespace passwall::core
