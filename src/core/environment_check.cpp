#include <sodium.h>
#include <sqlite3.h>

#include <iostream>

int main()
{
    if (sodium_init() < 0)
    {
        std::cerr << "Erreur : initialisation de libsodium impossible.\n";
        return 1;
    }

    std::cout << "libsodium : " << sodium_version_string() << '\n';
    std::cout << "SQLite : " << sqlite3_libversion() << '\n';
    std::cout << "Verification de l'environnement reussie.\n";
    return 0;
}
