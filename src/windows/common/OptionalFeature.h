// Copyright (C) Microsoft Corporation. All rights reserved.

#pragma once

#include <memory>
#include <string_view>

#include "defs.h"

namespace wsl::windows::common::optionalfeature {
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
} // namespace details

class Session
{
public:
    Session();
    ~Session();

    NON_COPYABLE(Session);
    NON_MOVABLE(Session);

    State GetState(std::wstring_view featureName);
    DWORD Enable(std::wstring_view featureName, DependencyBehavior dependencyBehavior);

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};
} // namespace wsl::windows::common::optionalfeature
