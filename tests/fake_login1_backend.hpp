#pragma once

#include "platform/linux_session_monitor.hpp"

#include <QTemporaryDir>

#include <deque>
#include <utility>
#include <vector>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>

namespace passwall::tests {

// Like logind: keep the FIFO's read side and transfer its NONBLOCK write side.
inline platform::InhibitorFd createFifoInhibitor(
    const QTemporaryDir& directory, std::vector<int>& peers)
{
    if (!directory.isValid())
        return platform::InhibitorFd{};
    const auto path = directory.filePath(QString::number(peers.size())).toLocal8Bit();
    if (::mkfifo(path.constData(), 0600) != 0)
        return platform::InhibitorFd{};
    const int reader = ::open(path.constData(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (reader < 0)
        return platform::InhibitorFd{};
    platform::InhibitorFd writer(::open(
        path.constData(), O_WRONLY | O_NONBLOCK | O_CLOEXEC));
    if (!writer.valid()) {
        ::close(reader);
        return writer;
    }
    peers.push_back(reader);
    return writer;
}

// No bus or system transition: FIFOs exist only in a private test directory.
class FakeLogin1Backend final : public platform::Login1Backend {
public:
    ~FakeLogin1Backend() override
    {
        for (const int peer : peers)
            ::close(peer);
    }
    void start() override { emit availabilityChanged(true); }
    void stop() override { inhibitors.clear(); snapshots.clear(); }
    void inhibit(InhibitResult result) override { inhibitors.push_back(std::move(result)); }
    void readState(StateResult result) override { snapshots.push_back(std::move(result)); }

    bool completeInhibit(bool success = true)
    {
        if (inhibitors.empty())
            return false;
        auto callback = std::move(inhibitors.front());
        inhibitors.pop_front();
        if (!success) {
            callback(platform::InhibitorFd{});
            return true;
        }
        auto fd = createFifoInhibitor(directory, peers);
        if (!fd.valid())
            return false;
        writers.push_back(fd.descriptor()); // borrowed, never closed by the fake
        if (breakOnInhibit)
            breakPeer(peers.size() - 1);
        callback(std::move(fd));
        return true;
    }
    bool completeState(std::optional<platform::Login1State> state = platform::Login1State{})
    {
        if (snapshots.empty())
            return false;
        auto callback = std::move(snapshots.front());
        snapshots.pop_front();
        callback(state);
        return true;
    }
    [[nodiscard]] bool inhibitorHeld(std::size_t index) const
    {
        if (index >= peers.size() || peers[index] < 0)
            return false;
        pollfd descriptor{peers[index], 0, 0};
        return ::poll(&descriptor, 1, 0) == 0;
    }
    void breakPeer(std::size_t index)
    {
        if (index < peers.size() && peers[index] >= 0)
            ::close(std::exchange(peers[index], -1));
    }

    std::deque<InhibitResult> inhibitors;
    std::deque<StateResult> snapshots;
    std::vector<int> peers;
    std::vector<int> writers;
    bool breakOnInhibit = false;
    QTemporaryDir directory{QStringLiteral("/tmp/passwall-fake-inhibitor-XXXXXX")};
};
} // namespace passwall::tests
