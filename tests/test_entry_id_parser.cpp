#include "native/entry_id_parser.hpp"

#include <gtest/gtest.h>

using passwall::models::EntryId;

TEST(EntryIdParserTest, DecodesCanonicalLowercaseHexToSixteenBytes)
{
    const EntryId expected = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };
    EntryId actual{};

    ASSERT_TRUE(passwall::native::parseCanonicalEntryId(
        QStringLiteral("000102030405060708090a0b0c0d0e0f"), actual));
    EXPECT_EQ(actual, expected);
}

TEST(EntryIdParserTest, RejectsTooShortIdentifier)
{
    EntryId entryId{};
    EXPECT_FALSE(passwall::native::parseCanonicalEntryId(
        QString(31, QLatin1Char('0')), entryId));
}

TEST(EntryIdParserTest, RejectsTooLongIdentifier)
{
    EntryId entryId{};
    EXPECT_FALSE(passwall::native::parseCanonicalEntryId(
        QString(33, QLatin1Char('0')), entryId));
}

TEST(EntryIdParserTest, RejectsNonHexCharacter)
{
    EntryId entryId{};
    EXPECT_FALSE(passwall::native::parseCanonicalEntryId(
        QStringLiteral("000102030405060708090g0b0c0d0e0f"), entryId));
}

TEST(EntryIdParserTest, RejectsLeadingAndTrailingWhitespace)
{
    EntryId entryId{};

    EXPECT_FALSE(passwall::native::parseCanonicalEntryId(
        QStringLiteral(" 000102030405060708090a0b0c0d0e0f"), entryId));
    EXPECT_FALSE(passwall::native::parseCanonicalEntryId(
        QStringLiteral("000102030405060708090a0b0c0d0e0f "), entryId));
}

TEST(EntryIdParserTest, RejectsSeparators)
{
    EntryId entryId{};
    EXPECT_FALSE(passwall::native::parseCanonicalEntryId(
        QStringLiteral("00010203-405060708090a0b0c0d0e0f"), entryId));
}

TEST(EntryIdParserTest, RejectsHexPrefix)
{
    EntryId entryId{};
    EXPECT_FALSE(passwall::native::parseCanonicalEntryId(
        QStringLiteral("0x0102030405060708090a0b0c0d0e0f"), entryId));
}

TEST(EntryIdParserTest, RejectsEmptyIdentifier)
{
    EntryId entryId{};
    EXPECT_FALSE(passwall::native::parseCanonicalEntryId(QString(), entryId));
}

TEST(EntryIdParserTest, RejectsUppercaseNonCanonicalRepresentation)
{
    EntryId entryId{};
    EXPECT_FALSE(passwall::native::parseCanonicalEntryId(
        QStringLiteral("000102030405060708090A0B0C0D0E0F"), entryId));
}
