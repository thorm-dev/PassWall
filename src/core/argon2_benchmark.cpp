
#include <sodium.h>

#include <array>
#include <charconv>
#include <chrono>
#include <iostream>
#include <string_view>

int main(int argc, char* argv[])
{
    if (sodium_init() < 0) {
        std::cerr << "Erreur : initialisation de libsodium impossible.\n";
        return 1;
    }

    int repetitions = 5;

    if (argc > 2) {
        std::cerr << "Usage : passwall_argon2_benchmark [nombre_essais]\n";
        return 1;
    }

    if (argc == 2) {
        const std::string_view argument(argv[1]);
        const auto result = std::from_chars(
            argument.data(),
            argument.data() + argument.size(),
            repetitions
        );

        if (result.ec != std::errc{} ||
            result.ptr != argument.data() + argument.size() ||
            repetitions < 1 ||
            repetitions > 100) {
            std::cerr << "Erreur : indique un nombre d'essais entre 1 et 100.\n";
            return 1;
        }
    }

    constexpr char password[] = "PassWall-benchmark-password";

    // Les nombres de passes restent inchangés.
    constexpr std::array<unsigned long long, 2> operationsLimits = {3, 4};

    constexpr std::array<std::size_t, 2> memoryLimits = {
        256ULL * 1024 * 1024,
        512ULL * 1024 * 1024
    };

    std::array<unsigned char, crypto_pwhash_SALTBYTES> salt{};
    std::array<unsigned char, 32> key{};

    randombytes_buf(salt.data(), salt.size());

    std::cout << "Nombre d'essais par combinaison : "
              << repetitions << "\n\n";

    for (const auto operations : operationsLimits) {
        for (const auto memory : memoryLimits) {
            std::cout << "Argon2id : " << operations
                      << " passe(s), "
                      << memory / (1024 * 1024)
                      << " Mio\n";

            long long totalMilliseconds = 0;

            for (int run = 1; run <= repetitions; ++run) {
                const auto start = std::chrono::steady_clock::now();

                const int result = crypto_pwhash(
                    key.data(),
                    key.size(),
                    password,
                    sizeof(password) - 1,
                    salt.data(),
                    operations,
                    memory,
                    crypto_pwhash_ALG_ARGON2ID13
                );

                const auto end = std::chrono::steady_clock::now();

                if (result != 0) {
                    sodium_memzero(key.data(), key.size());
                    sodium_memzero(salt.data(), salt.size());

                    std::cerr
                        << "Erreur : dérivation impossible, mémoire "
                        << "insuffisante ou paramètres refusés.\n";

                    return 1;
                }

                const auto elapsed =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        end - start
                    ).count();

                totalMilliseconds += elapsed;

                std::cout << "  Essai " << run
                          << " : " << elapsed << " ms\n";

                sodium_memzero(key.data(), key.size());
            }

            std::cout << "  Moyenne : "
                      << totalMilliseconds / repetitions
                      << " ms\n\n";
        }
    }

    sodium_memzero(key.data(), key.size());
    sodium_memzero(salt.data(), salt.size());

    std::cout << "Mesures terminées.\n";

    return 0;
}
