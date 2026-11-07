#include "core/site_matcher.hpp"

#include <gtest/gtest.h>

using passwall::core::SiteMatcher;

TEST(SiteMatcherTest, AcceptsSameOrigin)
{
    EXPECT_TRUE(SiteMatcher::matchesOrigin(
        "https://example.com/login",
        "https://example.com/account"));
}

TEST(SiteMatcherTest, RejectsDifferentScheme)
{
    EXPECT_FALSE(SiteMatcher::matchesOrigin(
        "http://example.com/login",
        "https://example.com/login"));
}

TEST(SiteMatcherTest, RejectsDifferentSubdomain)
{
    EXPECT_FALSE(SiteMatcher::matchesOrigin(
        "https://sub.example.com/login",
        "https://example.com/login"));
}

TEST(SiteMatcherTest, RejectsSimilarDomain)
{
    EXPECT_FALSE(SiteMatcher::matchesOrigin(
        "https://notexample.com/login",
        "https://example.com/login"));
}

TEST(SiteMatcherTest, RejectsDifferentPort)
{
    EXPECT_FALSE(SiteMatcher::matchesOrigin(
        "https://example.com:8443/login",
        "https://example.com/login"));
}

TEST(SiteMatcherTest, AcceptsEquivalentExplicitDefaultPort)
{
    EXPECT_TRUE(SiteMatcher::matchesOrigin(
        "https://example.com:443/login",
        "https://example.com/login"));
}

TEST(SiteMatcherTest, AcceptsHostCaseDifferences)
{
    EXPECT_TRUE(SiteMatcher::matchesOrigin(
        "https://EXAMPLE.com/login",
        "https://example.COM/account"));
}

TEST(SiteMatcherTest, AcceptsStoredUrlWithoutSchemeAsHttps)
{
    EXPECT_TRUE(SiteMatcher::matchesOrigin(
        "https://example.com/login",
        "example.com/account"));
}

TEST(SiteMatcherTest, RejectsMalformedRequestedUrl)
{
    EXPECT_FALSE(SiteMatcher::matchesOrigin(
        "https://",
        "https://example.com/login"));
}

TEST(SiteMatcherTest, RejectsRequestedUrlWithUserInfo)
{
    EXPECT_FALSE(SiteMatcher::matchesOrigin(
        "https://user:password@example.com/login",
        "https://example.com/login"));
}

TEST(SiteMatcherTest, RejectsStoredUrlWithUserInfo)
{
    EXPECT_FALSE(SiteMatcher::matchesOrigin(
        "https://example.com/login",
        "https://user:password@example.com/login"));
}

TEST(SiteMatcherTest, RejectsEmptyStoredUrl)
{
    EXPECT_FALSE(SiteMatcher::matchesOrigin(
        "https://example.com/login",
        ""));
}