#include <gtest/gtest.h>
#include <QSettings>
#include <QTemporaryDir>
#include <memory>

namespace {
// CRUD now consults the user registry. Never let standalone service regression
// binaries read, chmod or write the real user's PassWall settings, even when
// invoked directly or through CTest without a special environment variable.
class IsolatedVaultSettings final : public ::testing::Environment {
public:
    void SetUp() override
    {
        directory_ = std::make_unique<QTemporaryDir>();
        ASSERT_TRUE(directory_->isValid());
        for (auto format : {QSettings::NativeFormat, QSettings::IniFormat}) {
            QSettings::setPath(format, QSettings::UserScope, directory_->path());
            QSettings::setPath(format, QSettings::SystemScope, directory_->path());
        }
    }
private:
    std::unique_ptr<QTemporaryDir> directory_;
};
[[maybe_unused]] auto* const isolated =
    ::testing::AddGlobalTestEnvironment(new IsolatedVaultSettings);
}
