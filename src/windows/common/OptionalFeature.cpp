// Copyright (C) Microsoft Corporation. All rights reserved.

#include "precomp.h"
#include "OptionalFeature.h"

namespace {
using DismSession = unsigned int;

constexpr DismSession c_dismSessionDefault = 0;
constexpr auto c_dismOnlineImage = L"DISM_{53BFAE52-B167-4E2F-A258-0A37B57FF845}";
constexpr HRESULT c_dismReloadImageSessionRequired = 0x00000001;
std::mutex g_dismLock;

enum class DismLogLevel
{
    Errors = 0,
    ErrorsWarnings,
    ErrorsWarningsInfo
};

enum class DismPackageIdentifier
{
    None = 0
};

#pragma pack(push, 1)
struct DismFeatureInfo
{
    PCWSTR FeatureName;
    wsl::windows::common::optionalfeature::details::DismFeatureState FeatureState;
};
#pragma pack(pop)

struct DismProgressContext
{
    const wsl::windows::common::optionalfeature::ProgressObserver& Observer;
};

using DismInitializeFunction = HRESULT WINAPI(DismLogLevel, PCWSTR, PCWSTR);
using DismShutdownFunction = HRESULT WINAPI();
using DismOpenSessionFunction = HRESULT WINAPI(PCWSTR, PCWSTR, PCWSTR, DismSession*);
using DismCloseSessionFunction = HRESULT WINAPI(DismSession);
using DismGetFeatureInfoFunction = HRESULT WINAPI(DismSession, PCWSTR, PCWSTR, DismPackageIdentifier, DismFeatureInfo**);
using DismProgressCallback = void(CALLBACK*)(UINT, UINT, PVOID);
using DismEnableFeatureFunction = HRESULT WINAPI(
    DismSession, PCWSTR, PCWSTR, DismPackageIdentifier, BOOL, PCWSTR*, UINT, BOOL, HANDLE, DismProgressCallback, PVOID);
using DismDeleteFunction = HRESULT WINAPI(void*);

wil::shared_hmodule LoadDismApi()
{
    wil::shared_hmodule module{LoadLibraryExW(L"dismapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)};
    THROW_LAST_ERROR_IF(!module);
    return module;
}

void CALLBACK DismProgressCallbackImpl(UINT current, UINT total, PVOID userData) noexcept
{
    const auto* context = static_cast<const DismProgressContext*>(userData);
    if (context != nullptr)
    {
        wsl::windows::common::optionalfeature::details::InvokeProgressObserver(context->Observer, current, total);
    }
}
} // namespace

namespace wsl::windows::common::optionalfeature {
State details::MapDismFeatureState(DismFeatureState state)
{
    switch (state)
    {
    case DismFeatureState::NotPresent:
    case DismFeatureState::Staged:
    case DismFeatureState::Removed:
        return State::Disabled;

    case DismFeatureState::UninstallPending:
        return State::DisablePending;

    case DismFeatureState::Installed:
        return State::Enabled;

    case DismFeatureState::InstallPending:
        return State::EnablePending;

    default:
        THROW_HR_MSG(E_UNEXPECTED, "Unexpected DISM feature state: %u", static_cast<unsigned int>(state));
    }
}

void details::InvokeProgressObserver(const ProgressObserver& observer, unsigned int current, unsigned int total) noexcept
try
{
    if (observer)
    {
        observer(current, total);
    }
}
CATCH_LOG()

details::ThrottledProgressObserver::ThrottledProgressObserver(ProgressObserver observer) : m_observer{std::move(observer)}
{
    THROW_HR_IF(E_INVALIDARG, !m_observer);
}

void details::ThrottledProgressObserver::Report(unsigned int current, unsigned int total)
{
    const auto boundedCurrent = std::min(current, total);
    const auto bucket = total == 0 ? 0 : static_cast<unsigned int>((static_cast<uint64_t>(boundedCurrent) * c_progressBuckets) / total);
    const bool progressRestarted = m_hasReported && (current < m_previousCurrent);
    const bool shouldReport = !m_hasReported || (total != m_previousTotal) || progressRestarted || (total != 0 && bucket > m_previousBucket);
    if (!shouldReport)
    {
        return;
    }

    m_previousCurrent = current;
    m_previousTotal = total;
    m_previousBucket = bucket;
    m_hasReported = true;
    m_observer(current, total);
}

class Session::Impl
{
public:
    Impl() :
        m_dismLock{g_dismLock},
        m_module{LoadDismApi()},
        m_initialize{m_module, "DismInitialize"},
        m_shutdown{m_module, "DismShutdown"},
        m_openSession{m_module, "DismOpenSession"},
        m_closeSession{m_module, "DismCloseSession"},
        m_getFeatureInfo{m_module, "DismGetFeatureInfo"},
        m_enableFeature{m_module, "DismEnableFeature"},
        m_delete{m_module, "DismDelete"}
    {
        THROW_IF_FAILED(m_initialize(DismLogLevel::ErrorsWarnings, nullptr, nullptr));
        m_initialized = true;

        auto shutdownOnFailure = wil::scope_exit([&]() { LOG_IF_FAILED(m_shutdown()); });
        THROW_IF_FAILED(m_openSession(c_dismOnlineImage, nullptr, nullptr, &m_session));
        shutdownOnFailure.release();
    }

    ~Impl()
    {
        if (m_session != c_dismSessionDefault)
        {
            LOG_IF_FAILED(m_closeSession(m_session));
        }

        if (m_initialized)
        {
            LOG_IF_FAILED(m_shutdown());
        }
    }

    State GetState(std::wstring_view featureName)
    {
        THROW_HR_IF(E_INVALIDARG, featureName.empty());

        const std::wstring nullTerminatedName{featureName};
        DismFeatureInfo* featureInfo{};
        THROW_IF_FAILED(m_getFeatureInfo(m_session, nullTerminatedName.c_str(), nullptr, DismPackageIdentifier::None, &featureInfo));
        THROW_HR_IF(E_UNEXPECTED, featureInfo == nullptr);

        auto deleteFeatureInfo = wil::scope_exit([&]() { LOG_IF_FAILED(m_delete(featureInfo)); });
        return details::MapDismFeatureState(featureInfo->FeatureState);
    }

    DWORD Enable(std::wstring_view featureName, DependencyBehavior dependencyBehavior, const ProgressObserver& progressObserver)
    {
        THROW_HR_IF(E_INVALIDARG, featureName.empty());
        THROW_HR_IF(E_INVALIDARG, dependencyBehavior != DependencyBehavior::FeatureOnly && dependencyBehavior != DependencyBehavior::All);

        const std::wstring nullTerminatedName{featureName};
        DismProgressContext progressContext{progressObserver};
        const auto result = m_enableFeature(
            m_session,
            nullTerminatedName.c_str(),
            nullptr,
            DismPackageIdentifier::None,
            FALSE,
            nullptr,
            0,
            dependencyBehavior == DependencyBehavior::All ? TRUE : FALSE,
            nullptr,
            progressObserver ? DismProgressCallbackImpl : nullptr,
            progressObserver ? &progressContext : nullptr);

        if (result == c_dismReloadImageSessionRequired)
        {
            ReloadSession();
            return ERROR_SUCCESS;
        }

        return static_cast<DWORD>(result);
    }

private:
    void ReloadSession()
    {
        THROW_IF_FAILED(m_closeSession(m_session));
        m_session = c_dismSessionDefault;
        THROW_IF_FAILED(m_openSession(c_dismOnlineImage, nullptr, nullptr, &m_session));
    }

    std::unique_lock<std::mutex> m_dismLock;
    wil::shared_hmodule m_module;
    LxssDynamicFunction<DismInitializeFunction> m_initialize;
    LxssDynamicFunction<DismShutdownFunction> m_shutdown;
    LxssDynamicFunction<DismOpenSessionFunction> m_openSession;
    LxssDynamicFunction<DismCloseSessionFunction> m_closeSession;
    LxssDynamicFunction<DismGetFeatureInfoFunction> m_getFeatureInfo;
    LxssDynamicFunction<DismEnableFeatureFunction> m_enableFeature;
    LxssDynamicFunction<DismDeleteFunction> m_delete;
    DismSession m_session{c_dismSessionDefault};
    bool m_initialized{};
};

Session::Session() : m_impl{std::make_unique<Impl>()}
{
}

Session::~Session() = default;

State Session::GetState(std::wstring_view featureName)
{
    return m_impl->GetState(featureName);
}

DWORD Session::Enable(std::wstring_view featureName, DependencyBehavior dependencyBehavior, const ProgressObserver& progressObserver)
{
    return m_impl->Enable(featureName, dependencyBehavior, progressObserver);
}
} // namespace wsl::windows::common::optionalfeature
