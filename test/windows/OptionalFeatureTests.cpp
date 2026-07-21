// Copyright (C) Microsoft Corporation. All rights reserved.

#include "precomp.h"

#include "Common.h"
#include "OptionalFeature.h"
#include "WslInstall.h"

using wsl::windows::common::optionalfeature::DependencyBehavior;
using wsl::windows::common::optionalfeature::ProgressObserver;
using wsl::windows::common::optionalfeature::State;
using wsl::windows::common::optionalfeature::details::DismFeatureState;
using wsl::windows::common::optionalfeature::details::InvokeProgressObserver;
using wsl::windows::common::optionalfeature::details::MapDismFeatureState;
using wsl::windows::common::optionalfeature::details::ThrottledProgressObserver;

class OptionalFeatureTests
{
    WSL_TEST_CLASS(OptionalFeatureTests)

    TEST_METHOD(MapDismFeatureStates)
    {
        struct TestCase
        {
            DismFeatureState DismState;
            State ExpectedState;
        };

        constexpr std::array testCases{
            TestCase{DismFeatureState::NotPresent, State::Disabled},
            TestCase{DismFeatureState::Staged, State::Disabled},
            TestCase{DismFeatureState::Removed, State::Disabled},
            TestCase{DismFeatureState::UninstallPending, State::DisablePending},
            TestCase{DismFeatureState::Installed, State::Enabled},
            TestCase{DismFeatureState::InstallPending, State::EnablePending}};

        for (const auto& testCase : testCases)
        {
            VERIFY_ARE_EQUAL(
                static_cast<unsigned int>(testCase.ExpectedState), static_cast<unsigned int>(MapDismFeatureState(testCase.DismState)));
        }
    }

    TEST_METHOD(RejectUnsupportedDismFeatureStates)
    {
        constexpr std::array states{DismFeatureState::Superseded, DismFeatureState::PartiallyInstalled};
        for (const auto state : states)
        {
            const auto result = wil::ResultFromException([&]() { std::ignore = MapDismFeatureState(state); });

            VERIFY_ARE_EQUAL(E_UNEXPECTED, result);
        }
    }

    TEST_METHOD(EvaluateVirtualMachinePlatformStates)
    {
        struct TestCase
        {
            State FeatureState;
            bool RebootRequired;
            bool EnableFeature;
        };

        constexpr std::array testCases{
            TestCase{State::Enabled, false, false},
            TestCase{State::EnablePending, true, false},
            TestCase{State::Disabled, true, true},
            TestCase{State::DisablePending, true, false}};

        for (const auto& testCase : testCases)
        {
            const auto requirements = WslInstall::EvaluateOptionalComponentRequirements(false, [&](std::wstring_view featureName) {
                VERIFY_IS_TRUE(featureName == WslInstall::c_optionalFeatureNameVmp);
                return testCase.FeatureState;
            });

            VERIFY_ARE_EQUAL(testCase.RebootRequired, requirements.RebootRequired);
            VERIFY_ARE_EQUAL(testCase.EnableFeature ? 1u : 0u, static_cast<unsigned int>(requirements.ComponentsToEnable.size()));
            if (testCase.EnableFeature)
            {
                VERIFY_ARE_EQUAL(std::wstring{WslInstall::c_optionalFeatureNameVmp}, requirements.ComponentsToEnable.front());
            }
        }
    }

    TEST_METHOD(EvaluateRequiredWslFeature)
    {
        std::vector<std::wstring> queriedFeatures;
        const auto requirements = WslInstall::EvaluateOptionalComponentRequirements(true, [&](std::wstring_view featureName) {
            queriedFeatures.emplace_back(featureName);
            return featureName == WslInstall::c_optionalFeatureNameWsl ? State::Disabled : State::Enabled;
        });

        VERIFY_IS_TRUE(requirements.RebootRequired);
        VERIFY_ARE_EQUAL(2u, static_cast<unsigned int>(queriedFeatures.size()));
        VERIFY_ARE_EQUAL(std::wstring{WslInstall::c_optionalFeatureNameWsl}, queriedFeatures[0]);
        VERIFY_ARE_EQUAL(std::wstring{WslInstall::c_optionalFeatureNameVmp}, queriedFeatures[1]);
        VERIFY_ARE_EQUAL(1u, static_cast<unsigned int>(requirements.ComponentsToEnable.size()));
        VERIFY_ARE_EQUAL(std::wstring{WslInstall::c_optionalFeatureNameWsl}, requirements.ComponentsToEnable[0]);
    }

    TEST_METHOD(PropagateFeatureQueryFailure)
    {
        const auto result = wil::ResultFromException([]() {
            std::ignore = WslInstall::EvaluateOptionalComponentRequirements(
                false, [](std::wstring_view) -> State { THROW_HR(E_ACCESSDENIED); });
        });

        VERIFY_ARE_EQUAL(E_ACCESSDENIED, result);
    }

    TEST_METHOD(EnableOptionalComponentWithDependencies)
    {
        bool invoked{};
        const auto result = WslInstall::InstallOptionalComponent(
            WslInstall::c_optionalFeatureNameVmp,
            [&](std::wstring_view featureName, DependencyBehavior dependencyBehavior, const ProgressObserver& progressObserver) {
                invoked = true;
                VERIFY_IS_TRUE(featureName == WslInstall::c_optionalFeatureNameVmp);
                VERIFY_IS_TRUE(dependencyBehavior == DependencyBehavior::All);
                VERIFY_IS_FALSE(static_cast<bool>(progressObserver));
                return ERROR_SUCCESS;
            });

        VERIFY_IS_TRUE(invoked);
        VERIFY_ARE_EQUAL(static_cast<DWORD>(ERROR_SUCCESS), result);
    }

    TEST_METHOD(PreserveOptionalComponentRebootResult)
    {
        const auto result = WslInstall::InstallOptionalComponent(
            WslInstall::c_optionalFeatureNameVmp,
            [](std::wstring_view, DependencyBehavior, const ProgressObserver&) { return ERROR_SUCCESS_REBOOT_REQUIRED; });

        VERIFY_ARE_EQUAL(static_cast<DWORD>(ERROR_SUCCESS_REBOOT_REQUIRED), result);
    }

    TEST_METHOD(PropagateOptionalComponentEnableFailure)
    {
        constexpr auto nativeFailure = static_cast<DWORD>(E_ACCESSDENIED);
        const auto enableFeature = [](std::wstring_view, DependencyBehavior, const ProgressObserver& progressObserver) {
            if (progressObserver)
            {
                progressObserver(50, 100);
            }

            return nativeFailure;
        };

        VERIFY_ARE_EQUAL(nativeFailure, WslInstall::InstallOptionalComponent(WslInstall::c_optionalFeatureNameVmp, enableFeature));

        const auto result = wil::ResultFromException(
            [&]() { WslInstall::InstallOptionalComponents({WslInstall::c_optionalFeatureNameVmp}, enableFeature); });

        VERIFY_ARE_EQUAL(WSL_E_INSTALL_COMPONENT_FAILED, result);
    }

    TEST_METHOD(SequenceOptionalComponentEnables)
    {
        const std::vector<std::wstring> components{WslInstall::c_optionalFeatureNameWsl, WslInstall::c_optionalFeatureNameVmp};
        std::vector<std::wstring> enabledComponents;
        std::vector<DependencyBehavior> dependencyBehaviors;

        WslInstall::InstallOptionalComponents(
            components, [&](std::wstring_view featureName, DependencyBehavior dependencyBehavior, const ProgressObserver& progressObserver) {
                enabledComponents.emplace_back(featureName);
                dependencyBehaviors.emplace_back(dependencyBehavior);
                VERIFY_IS_TRUE(static_cast<bool>(progressObserver));
                progressObserver(0, 100);
                progressObserver(100, 100);
                return enabledComponents.size() == 1 ? ERROR_SUCCESS_REBOOT_REQUIRED : ERROR_SUCCESS;
            });

        VERIFY_ARE_EQUAL(components.size(), enabledComponents.size());
        VERIFY_IS_TRUE(components == enabledComponents);
        VERIFY_ARE_EQUAL(components.size(), dependencyBehaviors.size());
        VERIFY_IS_TRUE(std::ranges::all_of(dependencyBehaviors, [](DependencyBehavior dependencyBehavior) {
            return dependencyBehavior == DependencyBehavior::All;
        }));
    }

    TEST_METHOD(ThrottleOptionalComponentProgress)
    {
        std::vector<std::pair<unsigned int, unsigned int>> reports;
        ThrottledProgressObserver observer{[&](unsigned int current, unsigned int total) { reports.emplace_back(current, total); }};

        for (const auto current : {0u, 1u, 4u, 5u, 5u, 9u, 10u, 94u, 99u, 100u})
        {
            observer.Report(current, 100);
        }

        const std::vector<std::pair<unsigned int, unsigned int>> expected{{0, 100}, {5, 100}, {10, 100}, {94, 100}, {99, 100}, {100, 100}};
        VERIFY_IS_TRUE(reports == expected);
    }

    TEST_METHOD(ProgressObserverDoesNotEscapeCallbackBoundary)
    {
        unsigned int observedCurrent{};
        unsigned int observedTotal{};
        InvokeProgressObserver(
            [&](unsigned int current, unsigned int total) {
                observedCurrent = current;
                observedTotal = total;
            },
            25,
            100);

        VERIFY_ARE_EQUAL(25u, observedCurrent);
        VERIFY_ARE_EQUAL(100u, observedTotal);
        InvokeProgressObserver([](unsigned int, unsigned int) { THROW_HR(E_ABORT); }, 50, 100);
    }

    TEST_METHOD(ClassifyOptionalComponentFailures)
    {
        using Failure = WslInstall::OptionalComponentFailure;
        constexpr std::array<std::pair<DWORD, Failure>, 8> testCases{
            std::pair{0x800F0806u, Failure::ServicingPending},
            std::pair{0x800F0902u, Failure::ServicingPending},
            std::pair{0x800F081Fu, Failure::SourceUnavailable},
            std::pair{0x800F0906u, Failure::SourceUnavailable},
            std::pair{0x800F0907u, Failure::SourceUnavailable},
            std::pair{0x800F0954u, Failure::SourceUnavailable},
            std::pair{0x800F0831u, Failure::ComponentStoreCorruption},
            std::pair{static_cast<DWORD>(HRESULT_FROM_WIN32(ERROR_SXS_COMPONENT_STORE_CORRUPT)), Failure::ComponentStoreCorruption}};

        for (const auto& [error, expected] : testCases)
        {
            VERIFY_ARE_EQUAL(
                static_cast<unsigned int>(expected), static_cast<unsigned int>(WslInstall::ClassifyOptionalComponentFailure(error)));
        }
    }

    TEST_METHOD(PreserveUnknownOptionalComponentFailure)
    {
        constexpr DWORD unknownError = 0xDEADBEEF;
        VERIFY_IS_TRUE(WslInstall::ClassifyOptionalComponentFailure(unknownError) == WslInstall::OptionalComponentFailure::Unknown);

        const auto message =
            WslInstall::BuildOptionalComponentFailureMessage(WslInstall::c_optionalFeatureNameVmp, unknownError, L"C:\\Windows");
        VERIFY_IS_TRUE(message.find(L"VirtualMachinePlatform") != std::wstring::npos);
        VERIFY_IS_TRUE(message.find(L"0xDEADBEEF") != std::wstring::npos);
        VERIFY_IS_TRUE(message.find(L"C:\\Windows\\Logs\\DISM\\dism.log") != std::wstring::npos);
        VERIFY_IS_TRUE(message.find(L"C:\\Windows\\Logs\\CBS\\CBS.log") != std::wstring::npos);
        VERIFY_IS_TRUE(message.find(wsl::shared::Localization::MessageOptionalComponentServicingPending()) == std::wstring::npos);
        VERIFY_IS_TRUE(message.find(wsl::shared::Localization::MessageOptionalComponentSourceUnavailable()) == std::wstring::npos);
        VERIFY_IS_TRUE(message.find(wsl::shared::Localization::MessageOptionalComponentStoreCorruption()) == std::wstring::npos);
    }

    TEST_METHOD(BuildActionableOptionalComponentFailures)
    {
        struct TestCase
        {
            DWORD Error;
            std::wstring Guidance;
        };

        const std::array testCases{
            TestCase{0x800F0806u, wsl::shared::Localization::MessageOptionalComponentServicingPending()},
            TestCase{0x800F081Fu, wsl::shared::Localization::MessageOptionalComponentSourceUnavailable()},
            TestCase{0x800F0831u, wsl::shared::Localization::MessageOptionalComponentStoreCorruption()}};

        for (const auto& testCase : testCases)
        {
            const auto message = WslInstall::BuildOptionalComponentFailureMessage(
                WslInstall::c_optionalFeatureNameVmp, testCase.Error, L"C:\\Windows");
            VERIFY_IS_TRUE(message.find(std::format(L"0x{:08X}", testCase.Error)) != std::wstring::npos);
            VERIFY_IS_TRUE(message.find(testCase.Guidance) != std::wstring::npos);
            VERIFY_IS_TRUE(message.find(L"C:\\Windows\\Logs\\DISM\\dism.log") != std::wstring::npos);
            VERIFY_IS_TRUE(message.find(L"C:\\Windows\\Logs\\CBS\\CBS.log") != std::wstring::npos);
        }
    }
};
