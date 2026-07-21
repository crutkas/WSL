// Copyright (C) Microsoft Corporation. All rights reserved.

#pragma once

#include <functional>
#include <memory>
#include <string_view>

#include "defs.h"

namespace wsl::windows::common::optionalfeature {
using ProgressObserver = std::function<void(unsigned int current, unsigned int total)>;

enum class State
{
    Disabled = 0,
    DisablePending = 1,
    Enabled = 2,
    EnablePending = 3
};

enum class DependencyBehavior
{
    FeatureOnly,
    All
};

namespace details {
    enum class DismFeatureState : unsigned int
    {
        NotPresent = 0,
        UninstallPending = 1,
        Staged = 2,
        Removed = 3,
        Installed = 4,
        InstallPending = 5,
        Superseded = 6,
        PartiallyInstalled = 7
    };

    State MapDismFeatureState(DismFeatureState state);

    void InvokeProgressObserver(const ProgressObserver& observer, unsigned int current, unsigned int total) noexcept;

    class ThrottledProgressObserver
    {
    public:
        explicit ThrottledProgressObserver(ProgressObserver observer);

        void Report(unsigned int current, unsigned int total);

    private:
        static constexpr unsigned int c_progressBuckets = 20;

        ProgressObserver m_observer;
        unsigned int m_previousCurrent{};
        unsigned int m_previousTotal{};
        unsigned int m_previousBucket{};
        bool m_hasReported{};
    };
} // namespace details

class Session
{
public:
    Session();
    ~Session();

    NON_COPYABLE(Session);
    NON_MOVABLE(Session);

    State GetState(std::wstring_view featureName);
    DWORD Enable(std::wstring_view featureName, DependencyBehavior dependencyBehavior, const ProgressObserver& progressObserver = {});

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};
} // namespace wsl::windows::common::optionalfeature
