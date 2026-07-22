// Copyright (C) Microsoft Corporation. All rights reserved.

#pragma once

#include <DismApi.h>
#include <mutex>

#include "defs.h"

namespace wsl::windows::common::optionalfeature {
enum class State
{
    Disabled = 0,
    DisablePending,
    Enabled,
    EnablePending
};

namespace details {
    enum class EnableResult
    {
        Success,
        RebootRequired,
        ReloadRequired
    };

    State MapState(DismPackageFeatureState state);
    EnableResult InterpretEnableResult(HRESULT result);
} // namespace details

class Session
{
public:
    Session();
    ~Session();

    NON_COPYABLE(Session);
    NON_MOVABLE(Session);

    State GetState(PCWSTR featureName);
    bool Enable(PCWSTR featureName);

private:
    void Reload();

    std::unique_lock<std::mutex> m_lock;
    DismSession m_session{DISM_SESSION_DEFAULT};
};
} // namespace wsl::windows::common::optionalfeature
