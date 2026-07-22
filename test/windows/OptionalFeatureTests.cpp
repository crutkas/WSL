// Copyright (C) Microsoft Corporation. All rights reserved.

#include "precomp.h"

#include "Common.h"
#include "OptionalFeature.h"
#include "WslInstall.h"

using wsl::windows::common::optionalfeature::State;
using wsl::windows::common::optionalfeature::details::EnableResult;
using wsl::windows::common::optionalfeature::details::InterpretEnableResult;
using wsl::windows::common::optionalfeature::details::MapState;

class OptionalFeatureTests
{
    WSL_TEST_CLASS(OptionalFeatureTests)

    TEST_METHOD(MapDismFeatureStates)
    {
        struct TestCase
        {
            DismPackageFeatureState DismState;
            State ExpectedState;
        };

        constexpr std::array testCases{
            TestCase{DismStateNotPresent, State::Disabled},
            TestCase{DismStateStaged, State::Disabled},
            TestCase{DismStateRemoved, State::Disabled},
            TestCase{DismStateUninstallPending, State::DisablePending},
            TestCase{DismStateInstalled, State::Enabled},
            TestCase{DismStateInstallPending, State::EnablePending}};

        for (const auto& testCase : testCases)
        {
            VERIFY_ARE_EQUAL(static_cast<unsigned int>(testCase.ExpectedState), static_cast<unsigned int>(MapState(testCase.DismState)));
        }
    }

    TEST_METHOD(RejectUnsupportedDismFeatureStates)
    {
        constexpr std::array states{DismStateSuperseded, DismStatePartiallyInstalled};
        for (const auto state : states)
        {
            const auto result = wil::ResultFromException([&]() { std::ignore = MapState(state); });
            VERIFY_ARE_EQUAL(E_UNEXPECTED, result);
        }
    }

    TEST_METHOD(EvaluateOptionalFeatureStates)
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
            for (const bool testWslFeature : {false, true})
            {
                const auto requirements =
                    testWslFeature ? WslInstall::EvaluateOptionalComponentRequirements(true, testCase.FeatureState, State::Enabled)
                                   : WslInstall::EvaluateOptionalComponentRequirements(false, State::Enabled, testCase.FeatureState);

                VERIFY_ARE_EQUAL(testCase.RebootRequired, requirements.RebootRequired);
                VERIFY_ARE_EQUAL(testCase.EnableFeature ? 1u : 0u, static_cast<unsigned int>(requirements.ComponentsToEnable.size()));
                if (testCase.EnableFeature)
                {
                    VERIFY_ARE_EQUAL(
                        std::wstring{testWslFeature ? WslInstall::c_optionalFeatureNameWsl : WslInstall::c_optionalFeatureNameVmp},
                        requirements.ComponentsToEnable.front());
                }
            }
        }

        const auto ignoredWslFeature = WslInstall::EvaluateOptionalComponentRequirements(false, State::Disabled, State::Enabled);
        VERIFY_IS_FALSE(ignoredWslFeature.RebootRequired);
        VERIFY_IS_TRUE(ignoredWslFeature.ComponentsToEnable.empty());
    }

    TEST_METHOD(InterpretEnableResults)
    {
        struct TestCase
        {
            HRESULT NativeResult;
            EnableResult ExpectedResult;
        };

        constexpr std::array testCases{
            TestCase{S_OK, EnableResult::Success},
            TestCase{static_cast<HRESULT>(ERROR_SUCCESS_REBOOT_REQUIRED), EnableResult::RebootRequired},
            TestCase{HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED), EnableResult::RebootRequired},
            TestCase{DISMAPI_S_RELOAD_IMAGE_SESSION_REQUIRED, EnableResult::ReloadRequired}};

        for (const auto& testCase : testCases)
        {
            VERIFY_ARE_EQUAL(
                static_cast<unsigned int>(testCase.ExpectedResult), static_cast<unsigned int>(InterpretEnableResult(testCase.NativeResult)));
        }
    }

    TEST_METHOD(PreserveEnableFailures)
    {
        constexpr std::array failures{E_ACCESSDENIED, E_FAIL};
        for (const auto failure : failures)
        {
            const auto result = wil::ResultFromException([&]() { std::ignore = InterpretEnableResult(failure); });
            VERIFY_ARE_EQUAL(failure, result);
        }

        const auto result = wil::ResultFromException([]() { std::ignore = InterpretEnableResult(2); });
        VERIFY_ARE_EQUAL(E_UNEXPECTED, result);
    }
};
