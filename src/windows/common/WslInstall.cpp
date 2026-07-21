/*++

Copyright (c) Microsoft. All rights reserved.

Module Name:

    WslInstall.cpp

Abstract:

    This file contains implementations for installing WSL distributions

--*/

#include "precomp.h"
#include "WslInstall.h"
#include "wslutil.h"
#include "ConsoleProgressBar.h"
#include "Distribution.h"
#include "HandleConsoleProgressBar.h"
#include "svccomm.hpp"

extern HINSTANCE g_dllInstance;

using wsl::shared::Localization;
using namespace wsl::windows::common::distribution;
using namespace wsl::windows::common::wslutil;

namespace {
constexpr DWORD c_cbsPending = 0x800F0806;
constexpr DWORD c_cbsSourceMissing = 0x800F081F;
constexpr DWORD c_cbsStoreCorruption = 0x800F0831;
constexpr DWORD c_cbsBusy = 0x800F0902;
constexpr DWORD c_cbsDownloadFailure = 0x800F0906;
constexpr DWORD c_cbsGroupPolicyDisallowed = 0x800F0907;
constexpr DWORD c_cbsInvalidWindowsUpdateCountWsus = 0x800F0954;

void EnforceFileHash(HANDLE file, const std::wstring& expectedHash)
{
    wsl::windows::common::ExecutionContext context(wsl::windows::common::VerifyChecksum);

    const auto fileHash = wsl::windows::common::wslutil::HashFile(file, CALG_SHA_256);

    THROW_LAST_ERROR_IF(SetFilePointer(file, 0, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER);
    if (fileHash != wsl::windows::common::string::HexToBytes(expectedHash))
    {
        THROW_HR_WITH_USER_ERROR(
            TRUST_E_BAD_DIGEST,
            wsl::shared::Localization::MessageHashMismatch(
                expectedHash.c_str(), wsl::windows::common::string::BytesToHex(fileHash).c_str()));
    }
}

void AddOptionalComponentRequirement(
    WslInstall::OptionalComponentRequirements& requirements, std::wstring_view component, wsl::windows::common::optionalfeature::State state)
{
    switch (state)
    {
    case wsl::windows::common::optionalfeature::State::Enabled:
        return;

    case wsl::windows::common::optionalfeature::State::EnablePending:
    case wsl::windows::common::optionalfeature::State::DisablePending:
        requirements.RebootRequired = true;
        return;

    case wsl::windows::common::optionalfeature::State::Disabled:
        requirements.RebootRequired = true;
        requirements.ComponentsToEnable.emplace_back(component);
        return;

    default:
        THROW_HR(E_UNEXPECTED);
    }
}

}; // namespace

HRESULT WslInstall::InstallDistribution(
    _Out_ InstallResult& installResult,
    _In_ const std::optional<std::wstring>& distributionName,
    _In_ const std::optional<ULONG>& version,
    _In_ bool launchAfterInstall,
    _In_ bool useGitHub,
    _In_ bool legacy,
    _In_ bool fixedVhd,
    _In_ const std::optional<std::wstring>& localName,
    _In_ const std::optional<std::wstring>& location,
    _In_ const std::optional<uint64_t>& vhdSize)
try
{
    wsl::windows::common::ExecutionContext context(wsl::windows::common::InstallDistro);

    try
    {
        const auto distributions = wsl::windows::common::distribution::GetAvailable();

        if (distributionName.has_value())
        {
            installResult.Distribution = LookupByName(distributions, distributionName->c_str(), legacy);
        }
        else
        {
            if (legacy)
            {
                THROW_HR_IF(
                    E_UNEXPECTED, !distributions.Manifest.Distributions.has_value() || distributions.Manifest.Distributions->empty());
                installResult.Distribution = (*distributions.Manifest.Distributions)[0];
            }
            else
            {
                if (distributions.OverrideManifest.has_value() && distributions.OverrideManifest->Default.has_value())
                {
                    installResult.Distribution = LookupByName(distributions, distributions.OverrideManifest->Default->c_str(), false);
                }
                else
                {
                    if (!distributions.Manifest.Default.has_value())
                    {
                        THROW_HR_WITH_USER_ERROR(E_UNEXPECTED, wsl::shared::Localization::MessageNoInstallDefault());
                    }

                    installResult.Distribution = LookupByName(distributions, distributions.Manifest.Default->c_str(), false);
                }
            }
        }

        if (const auto* distro = std::get_if<ModernDistributionVersion>(&*installResult.Distribution))
        {
            std::tie(installResult.Name, installResult.Id) =
                InstallModernDistribution(*distro, version, localName, location, vhdSize, fixedVhd);

            installResult.InstalledViaGitHub = true;
        }
        else if (const auto* distro = std::get_if<Distribution>(&*installResult.Distribution))
        {
            std::list<std::pair<bool, LPCWSTR>> unsupportedArguments = {
                {localName.has_value(), WSL_INSTALL_ARG_NAME_LONG},
                {location.has_value(), WSL_INSTALL_ARG_LOCATION_LONG},
                {vhdSize.has_value(), WSL_INSTALL_ARG_VHD_SIZE},
                {fixedVhd, WSL_INSTALL_ARG_FIXED_VHD}};

            for (const auto& [condition, argument] : unsupportedArguments)
            {
                if (condition)
                {
                    THROW_HR_WITH_USER_ERROR(WSL_E_INVALID_USAGE, Localization::MessageNotSupportedOnLegacyDistros(argument).c_str());
                }
            }

            installResult.Alreadyinstalled = wsl::windows::common::distribution::IsInstalled(*distro, useGitHub);
            if (!installResult.Alreadyinstalled)
            {
                EMIT_USER_WARNING(Localization::MessageUsingLegacyDistribution());
                if (version.has_value())
                {
                    THROW_HR_WITH_USER_ERROR(WSL_E_INVALID_USAGE, Localization::MessageLegacyDistributionVersionArgNotSupported());
                }

                // If downloading from the store fails, attempt to download from GitHub.
                if (!useGitHub)
                {
                    auto hr =
                        wil::ResultFromException([&]() { wsl::windows::common::distribution::LegacyInstallViaStore(*distro); });
                    if (FAILED(hr))
                    {
                        useGitHub = true;
                        auto errorString = wsl::windows::common::wslutil::GetErrorString(hr);
                        wsl::windows::common::wslutil::PrintMessage(
                            Localization::MessageDistroStoreInstallFailed(distro->Name.c_str(), errorString.c_str()), stdout);
                    }
                }

                if (useGitHub)
                {
                    wsl::windows::common::distribution::LegacyInstallViaGithub(*distro);
                }
            }

            installResult.Name = distro->FriendlyName;
            installResult.InstalledViaGitHub = useGitHub;
        }
        else
        {
            THROW_HR(E_UNEXPECTED);
        }
    }
    catch (...)
    {
        // Rethrowing via WIL is required for the error context to be properly set
        // in case a winrt exception was thrown.
        THROW_HR(wil::ResultFromCaughtException());
    }

    return S_OK;
}
CATCH_RETURN()

WslInstall::OptionalComponentRequirements WslInstall::CheckForMissingOptionalComponents(_In_ bool requireWslOptionalComponent)
{
    wsl::windows::common::optionalfeature::Session session;
    return CheckForMissingOptionalComponents(
        requireWslOptionalComponent, [&](std::wstring_view featureName) { return session.GetState(featureName); });
}

WslInstall::OptionalComponentRequirements WslInstall::CheckForMissingOptionalComponents(_In_ bool requireWslOptionalComponent, const OptionalFeatureStateQuery& queryFeatureState)
{
    requireWslOptionalComponent |= !wsl::windows::common::helpers::IsWindows11OrAbove();
    return EvaluateOptionalComponentRequirements(requireWslOptionalComponent, queryFeatureState);
}

WslInstall::OptionalComponentRequirements WslInstall::EvaluateOptionalComponentRequirements(
    _In_ bool requireWslOptionalComponent, const OptionalFeatureStateQuery& queryFeatureState)
{
    THROW_HR_IF(E_INVALIDARG, !queryFeatureState);

    OptionalComponentRequirements requirements;
    if (requireWslOptionalComponent)
    {
        AddOptionalComponentRequirement(requirements, c_optionalFeatureNameWsl, queryFeatureState(c_optionalFeatureNameWsl));
    }

    AddOptionalComponentRequirement(requirements, c_optionalFeatureNameVmp, queryFeatureState(c_optionalFeatureNameVmp));
    return requirements;
}

DWORD WslInstall::InstallOptionalComponent(std::wstring_view component)
{
    wsl::windows::common::optionalfeature::Session session;
    return InstallOptionalComponent(
        component,
        [&](std::wstring_view featureName,
            wsl::windows::common::optionalfeature::DependencyBehavior dependencyBehavior,
            const wsl::windows::common::optionalfeature::ProgressObserver& progressObserver) {
            return session.Enable(featureName, dependencyBehavior, progressObserver);
        });
}

void WslInstall::InstallOptionalComponents(const std::vector<std::wstring>& components)
{
    if (components.empty())
    {
        return;
    }

    wsl::windows::common::optionalfeature::Session session;
    InstallOptionalComponents(
        components,
        [&](std::wstring_view featureName,
            wsl::windows::common::optionalfeature::DependencyBehavior dependencyBehavior,
            const wsl::windows::common::optionalfeature::ProgressObserver& progressObserver) {
            return session.Enable(featureName, dependencyBehavior, progressObserver);
        });
}

void WslInstall::InstallOptionalComponents(const std::vector<std::wstring>& components, const OptionalFeatureEnable& enableFeature)
{
    THROW_HR_IF(E_INVALIDARG, !enableFeature);

    for (const auto& component : components)
    {
        wsl::windows::common::wslutil::PrintMessage(Localization::MessageInstallingWindowsComponent(component));

        wsl::windows::common::ConsoleProgressBar progressBar;
        auto clearProgress = wil::scope_exit([&]() { LOG_IF_FAILED(progressBar.Clear()); });
        wsl::windows::common::optionalfeature::details::ThrottledProgressObserver progressObserver{
            [&](unsigned int current, unsigned int total) { THROW_IF_FAILED(progressBar.Print(current, total)); }};

        const auto exitCode =
            enableFeature(component, wsl::windows::common::optionalfeature::DependencyBehavior::All, [&](auto current, auto total) {
                progressObserver.Report(current, total);
            });
        if (exitCode != 0 && exitCode != ERROR_SUCCESS_REBOOT_REQUIRED)
        {
            THROW_HR_WITH_USER_ERROR(
                WSL_E_INSTALL_COMPONENT_FAILED,
                BuildOptionalComponentFailureMessage(component, exitCode, wil::GetWindowsDirectoryW<std::wstring>()));
        }
    }
}

DWORD WslInstall::InstallOptionalComponent(std::wstring_view component, const OptionalFeatureEnable& enableFeature)
{
    THROW_HR_IF(E_INVALIDARG, component.empty() || !enableFeature);
    return enableFeature(component, wsl::windows::common::optionalfeature::DependencyBehavior::All, {});
}

WslInstall::OptionalComponentFailure WslInstall::ClassifyOptionalComponentFailure(DWORD error)
{
    switch (error)
    {
    case c_cbsPending:
    case c_cbsBusy:
        return OptionalComponentFailure::ServicingPending;

    case c_cbsSourceMissing:
    case c_cbsDownloadFailure:
    case c_cbsGroupPolicyDisallowed:
    case c_cbsInvalidWindowsUpdateCountWsus:
        return OptionalComponentFailure::SourceUnavailable;

    case c_cbsStoreCorruption:
    case static_cast<DWORD>(HRESULT_FROM_WIN32(ERROR_SXS_COMPONENT_STORE_CORRUPT)):
        return OptionalComponentFailure::ComponentStoreCorruption;

    default:
        return OptionalComponentFailure::Unknown;
    }
}

std::wstring WslInstall::BuildOptionalComponentFailureMessage(std::wstring_view component, DWORD error, std::wstring_view windowsDirectory)
{
    THROW_HR_IF(E_INVALIDARG, component.empty() || windowsDirectory.empty());

    auto message = Localization::MessageOptionalComponentInstallFailed(component, std::format(L"0x{:08X}", error));
    switch (ClassifyOptionalComponentFailure(error))
    {
    case OptionalComponentFailure::ServicingPending:
        message += L'\n' + Localization::MessageOptionalComponentServicingPending();
        break;

    case OptionalComponentFailure::SourceUnavailable:
        message += L'\n' + Localization::MessageOptionalComponentSourceUnavailable();
        break;

    case OptionalComponentFailure::ComponentStoreCorruption:
        message += L'\n' + Localization::MessageOptionalComponentStoreCorruption();
        break;

    case OptionalComponentFailure::Unknown:
        break;
    }

    const std::filesystem::path windowsPath{windowsDirectory};
    message += L'\n' + Localization::MessageOptionalComponentServicingLogs(
                           (windowsPath / L"Logs" / L"DISM" / L"dism.log").wstring(),
                           (windowsPath / L"Logs" / L"CBS" / L"CBS.log").wstring());
    return message;
}

std::pair<std::wstring, GUID> WslInstall::InstallModernDistribution(
    const ModernDistributionVersion& distribution,
    const std::optional<ULONG>& version,
    const std::optional<std::wstring>& name,
    const std::optional<std::wstring>& location,
    const std::optional<uint64_t>& vhdSize,
    const bool fixedVhd)
{
    wsl::windows::common::SvcComm service;

    // Fail early if the distributions name is already in use.
    auto result = wil::ResultFromException([&]() {
        service.GetDistributionId(name.has_value() ? name->c_str() : distribution.Name.c_str(), LXSS_GET_DISTRO_ID_LIST_ALL);
    });

    THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS), SUCCEEDED(result));
    LOG_HR_IF(result, result != WSL_E_DISTRO_NOT_FOUND);

    const auto downloadInfo = wsl::shared::Arm64 ? distribution.Arm64Url : distribution.Amd64Url;
    THROW_HR_IF(E_UNEXPECTED, !downloadInfo.has_value());

    std::wstring installPath;
    bool fileDownloaded{};
    auto deleteFile = wil::scope_exit_log(WI_DIAGNOSTICS_INFO, [&] {
        if (fileDownloaded)
        {
            THROW_IF_WIN32_BOOL_FALSE(DeleteFileW(installPath.c_str()));
        }
    });

    if (auto localFile = wsl::windows::common::filesystem::TryGetPathFromFileUrl(downloadInfo->Url))
    {
        installPath = std::move(localFile.value());
    }
    else
    {
        PrintMessage(Localization::MessageDownloading(distribution.FriendlyName.c_str()), stdout);
        installPath = DownloadFile(downloadInfo->Url, distribution.Name + L".wsl");
        fileDownloaded = true;
    }

    PrintMessage(Localization::MessageInstalling(distribution.FriendlyName.c_str()), stdout);

    wil::unique_handle file{CreateFile(installPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr)};
    THROW_LAST_ERROR_IF(!file);

    EnforceFileHash(file.get(), downloadInfo->Sha256);

    wsl::windows::common::HandleConsoleProgressBar progressBar(file.get(), Localization::MessageImportProgress());

    auto [id, installedName] = service.RegisterDistribution(
        name.has_value() ? name->c_str() : distribution.Name.c_str(),
        version.value_or(LXSS_WSL_VERSION_DEFAULT),
        file.get(),
        location.has_value() ? location->c_str() : nullptr,
        fixedVhd ? LXSS_IMPORT_DISTRO_FLAGS_FIXED_VHD : 0,
        vhdSize);

    return {installedName.get(), id};
}