
#include "core/password_generator.hpp"

#include <gtest/gtest.h>

#include <string>

using passwall::core::PasswordGenerator;
using passwall::core::PasswordOptions;

TEST(PasswordGenerator, GeneratesPasswordOfRequestedLength)
{
    PasswordOptions options;
    options.length = 32;

    std::string password;
    std::string error;

    ASSERT_TRUE(PasswordGenerator::generate(options, password, error))
        << error;

    EXPECT_EQ(password.size(), 32);
}

TEST(PasswordGenerator, IncludesEverySelectedCharacterType)
{
    PasswordOptions options;
    options.length = 32;

    std::string password;
    std::string error;

    ASSERT_TRUE(PasswordGenerator::generate(options, password, error))
        << error;

    EXPECT_TRUE(password.find_first_of("abcdefghijkmnopqrstuvwxyz")
                != std::string::npos);
    EXPECT_TRUE(password.find_first_of("ABCDEFGHJKLMNPQRSTUVWXYZ")
                != std::string::npos);
    EXPECT_TRUE(password.find_first_of("23456789")
                != std::string::npos);
    EXPECT_TRUE(password.find_first_of("!@#$%^&*()-_=+[]{}:,.?")
                != std::string::npos);
}

TEST(PasswordGenerator, SupportsOnlySelectedCharacterTypes)
{
    PasswordOptions options;
    options.length = 20;
    options.lowercase = false;
    options.uppercase = false;
    options.digits = true;
    options.symbols = false;

    std::string password;
    std::string error;

    ASSERT_TRUE(PasswordGenerator::generate(options, password, error))
        << error;

    EXPECT_EQ(password.size(), 20);

    for (const char c : password) {
        EXPECT_NE(std::string("23456789").find(c), std::string::npos);
    }
}

TEST(PasswordGenerator, RejectsInvalidLength)
{
    PasswordOptions options;
    options.length = 4;

    std::string password;
    std::string error;

    EXPECT_FALSE(PasswordGenerator::generate(options, password, error));
    EXPECT_FALSE(error.empty());
}

TEST(PasswordGenerator, RejectsEmptyCharacterSelection)
{
    PasswordOptions options;
    options.length = 20;
    options.lowercase = false;
    options.uppercase = false;
    options.digits = false;
    options.symbols = false;

    std::string password;
    std::string error;

    EXPECT_FALSE(PasswordGenerator::generate(options, password, error));
    EXPECT_FALSE(error.empty());
}
