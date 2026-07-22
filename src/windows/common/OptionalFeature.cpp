// Copyright (C) Microsoft Corporation. All rights reserved.

#include "precomp.h"
#include "OptionalFeature.h"

namespace {
std::mutex g_dismLock;
}

namespace wsl::windows::common::optionalfeature {
State details::MapState(DismPackageFeatureState state)
{
    switch (state)
    {
    case DismStateNotPresent:
    case DismStateStaged:
    case DismStateRemoved:
        return State::Disabled;

    case DismStateUninstallPending:
        return State::DisablePending;

    case DismStateInstalled:
        return State::Enabled;

    case DismStateInstallPending:
        return State::EnablePending;

    default:
        THROW_HR_MSG(E_UNEXPECTED, "Unexpected DISM feature state: %u", static_cast<unsigned int>(state));
    }
}

details::EnableResult details::InterpretEnableResult(HRESULT result)
{
    if (result == S_OK)
    {
        return EnableResult::Success;
    }

    if (result == static_cast<HRESULT>(ERROR_SUCCESS_REBOOT_REQUIRED) || result == HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED))
    {
        return EnableResult::RebootRequired;
    }

    if (result == DISMAPI_S_RELOAD_IMAGE_SESSION_REQUIRED)
    {
        return EnableResult::ReloadRequired;
    }

    THROW_IF_FAILED(result);
    THROW_HR_MSG(E_UNEXPECTED, "Unexpected successful DISM enable result: 0x%08X", result);
}

Session::Session() : m_lock{g_dismLock}
{
    THROW_IF_FAILED(DismInitialize(DismLogErrorsWarnings, nullptr, nullptr));
    auto shutdownOnFailure = wil::scope_exit([]() { LOG_IF_FAILED(DismShutdown()); });

    THROW_IF_FAILED(DismOpenSession(DISM_ONLINE_IMAGE, nullptr, nullptr, &m_session));
    shutdownOnFailure.release();
}

Session::~Session()
{
    if (m_session != DISM_SESSION_DEFAULT)
    {
        LOG_IF_FAILED(DismCloseSession(m_session));
    }

    LOG_IF_FAILED(DismShutdown());
}

State Session::GetState(PCWSTR featureName)
{
    THROW_HR_IF(E_INVALIDARG, featureName == nullptr || *featureName == L'\0');

    DismFeatureInfo* featureInfo{};
    THROW_IF_FAILED(DismGetFeatureInfo(m_session, featureName, nullptr, DismPackageNone, &featureInfo));
    THROW_HR_IF(E_UNEXPECTED, featureInfo == nullptr);

    auto deleteFeatureInfo = wil::scope_exit([&]() { LOG_IF_FAILED(DismDelete(featureInfo)); });
    return details::MapState(featureInfo->FeatureState);
}

bool Session::Enable(PCWSTR featureName)
{
    THROW_HR_IF(E_INVALIDARG, featureName == nullptr || *featureName == L'\0');

    const auto result = details::InterpretEnableResult(
        DismEnableFeature(m_session, featureName, nullptr, DismPackageNone, FALSE, nullptr, 0, TRUE, nullptr, nullptr, nullptr));

    if (result == details::EnableResult::ReloadRequired)
    {
        Reload();
    }

    return result == details::EnableResult::RebootRequired;
}

void Session::Reload()
{
    THROW_IF_FAILED(DismCloseSession(m_session));
    m_session = DISM_SESSION_DEFAULT;
    THROW_IF_FAILED(DismOpenSession(DISM_ONLINE_IMAGE, nullptr, nullptr, &m_session));
}
} // namespace wsl::windows::common::optionalfeature
