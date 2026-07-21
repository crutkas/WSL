// Copyright (C) Microsoft Corporation. All rights reserved.

#include "precomp.h"

#include "Common.h"
#include "InstallResume.h"

using namespace wsl::windows::common::installresume;

namespace {

GUID ParseGuid(std::wstring_view value)
{
    const auto parsed = GuidFromString(value);
    VERIFY_IS_TRUE(parsed.has_value());
    return parsed.value_or(GUID{});
}

RawRegistryValue MakeStringValue(std::wstring_view value)
{
    const std::wstring nullTerminated{value};
    RawRegistryValue raw;
    raw.Type = REG_SZ;
    raw.Size = gsl::narrow_cast<DWORD>((nullTerminated.size() + 1) * sizeof(WCHAR));
    raw.Data.resize(raw.Size);
    memcpy(raw.Data.data(), nullTerminated.c_str(), raw.Size);
    return raw;
}

State MakeState(const GUID& generation, const GUID& bootId)
{
    State state;
    state.Generation = generation;
    state.WriterVersion = L"1.2.3";
    state.LastAutomaticBootId = bootId;
    state.InstallIntent.Selector = DistributionSelector::Explicit;
    state.InstallIntent.Distribution = L"Ubuntu";
    return state;
}

void VerifyIntentEqual(const Intent& expected, const Intent& actual)
{
    VERIFY_IS_TRUE(expected.Selector == actual.Selector);
    VERIFY_IS_TRUE(expected.Distribution == actual.Distribution);
    VERIFY_IS_TRUE(expected.Name == actual.Name);
    VERIFY_IS_TRUE(expected.Location == actual.Location);
    VERIFY_IS_TRUE(expected.Version == actual.Version);
    VERIFY_IS_TRUE(expected.VhdSize == actual.VhdSize);
    VERIFY_ARE_EQUAL(expected.FixedVhd, actual.FixedVhd);
    VERIFY_ARE_EQUAL(expected.Legacy, actual.Legacy);
    VERIFY_ARE_EQUAL(expected.WebDownload, actual.WebDownload);
    VERIFY_ARE_EQUAL(expected.EnableWsl1, actual.EnableWsl1);
    VERIFY_ARE_EQUAL(expected.NoLaunch, actual.NoLaunch);
}

template <typename TCallback>
void VerifyInvalidState(TCallback&& callback)
{
    VERIFY_IS_TRUE(FAILED(wil::ResultFromException(std::forward<TCallback>(callback))));
}

class MemoryStore final : public Store
{
public:
    std::optional<RawRegistryValue> ReadState() const override
    {
        return StateValue;
    }

    std::optional<RawRegistryValue> ReadTrigger() const override
    {
        return TriggerValue;
    }

    void WriteState(std::wstring_view value) override
    {
        StateValue = MakeStringValue(value);
    }

    void WriteTrigger(std::wstring_view value) override
    {
        TriggerValue = MakeStringValue(value);
    }

    void DeleteState() override
    {
        StateValue.reset();
    }

    void DeleteTrigger() override
    {
        TriggerValue.reset();
    }

    void QuarantineState(std::wstring_view) override
    {
        QuarantinedValue = StateValue;
        StateValue.reset();
    }

    std::optional<RawRegistryValue> StateValue;
    std::optional<RawRegistryValue> TriggerValue;
    std::optional<RawRegistryValue> QuarantinedValue;
};

} // namespace

class InstallResumeTests
{
    WSL_TEST_CLASS(InstallResumeTests)

    TEST_METHOD(RoundTripModernIntent)
    {
        const auto generation = ParseGuid(L"{11111111-1111-1111-1111-111111111111}");
        const auto bootId = ParseGuid(L"{22222222-2222-2222-2222-222222222222}");
        auto state = MakeState(generation, bootId);
        state.InstallIntent.Name = L"Dev";
        state.InstallIntent.Location = CanonicalizeLocation(L"C:\\WSL\\Dev");
        state.InstallIntent.Version = LXSS_WSL_VERSION_2;
        state.InstallIntent.VhdSize = 64ull * 1024 * 1024 * 1024;
        state.InstallIntent.FixedVhd = true;
        state.InstallIntent.WebDownload = true;
        state.InstallIntent.EnableWsl1 = true;
        state.InstallIntent.NoLaunch = true;

        const auto serialized = SerializeState(state);
        const auto decoded = DecodeState(MakeStringValue(serialized));

        VERIFY_IS_TRUE(decoded.Kind == StateValueKind::Valid);
        VERIFY_IS_TRUE(AreEqual(generation, decoded.Value->Generation));
        VERIFY_IS_TRUE(AreEqual(bootId, decoded.Value->LastAutomaticBootId));
        VERIFY_ARE_EQUAL(state.WriterVersion, decoded.Value->WriterVersion);
        VerifyIntentEqual(state.InstallIntent, decoded.Value->InstallIntent);
        VERIFY_IS_TRUE(serialized.find(L"commandLine") == serialized.npos);
        VERIFY_IS_TRUE(serialized.find(L"fromFile") == serialized.npos);
        VERIFY_IS_TRUE(serialized.find(L"stdin") == serialized.npos);
        VERIFY_IS_TRUE(serialized.find(L"password") == serialized.npos);
    }

    TEST_METHOD(RoundTripLegacyIntent)
    {
        auto state = MakeState(ParseGuid(L"{11111111-1111-1111-1111-111111111111}"), ParseGuid(L"{22222222-2222-2222-2222-222222222222}"));
        state.InstallIntent.Legacy = true;
        state.InstallIntent.WebDownload = true;

        const auto decoded = DecodeState(MakeStringValue(SerializeState(state)));
        VERIFY_IS_TRUE(decoded.Kind == StateValueKind::Valid);
        VerifyIntentEqual(state.InstallIntent, decoded.Value->InstallIntent);
    }

    TEST_METHOD(RoundTripRegistrationCheckpoints)
    {
        auto state = MakeState(ParseGuid(L"{11111111-1111-1111-1111-111111111111}"), ParseGuid(L"{22222222-2222-2222-2222-222222222222}"));
        state.CurrentPhase = Phase::InstallingDistribution;
        state.DistroRegistration.Status = RegistrationStatus::Started;
        state.DistroRegistration.DistributionName = L"Ubuntu";
        state.DistroRegistration.TargetName = L"Dev";

        auto decoded = DecodeState(MakeStringValue(SerializeState(state)));
        VERIFY_IS_TRUE(decoded.Kind == StateValueKind::Valid);
        VERIFY_IS_TRUE(decoded.Value->DistroRegistration.Status == RegistrationStatus::Started);

        state.CurrentPhase = Phase::DistributionCommitted;
        state.DistroRegistration.Status = RegistrationStatus::Committed;
        state.DistroRegistration.InstalledName = L"Dev";
        state.DistroRegistration.CommittedId = ParseGuid(L"{33333333-3333-3333-3333-333333333333}");
        decoded = DecodeState(MakeStringValue(SerializeState(state)));
        VERIFY_IS_TRUE(decoded.Kind == StateValueKind::Valid);
        VERIFY_IS_TRUE(AreEqual(*state.DistroRegistration.CommittedId, *decoded.Value->DistroRegistration.CommittedId));
    }

    TEST_METHOD(RejectInvalidIntentCombinations)
    {
        auto state = MakeState(ParseGuid(L"{11111111-1111-1111-1111-111111111111}"), ParseGuid(L"{22222222-2222-2222-2222-222222222222}"));

        state.InstallIntent.FixedVhd = true;
        VerifyInvalidState([&]() { std::ignore = SerializeState(state); });

        state.InstallIntent.VhdSize = 1024;
        state.InstallIntent.Version = LXSS_WSL_VERSION_1;
        VerifyInvalidState([&]() { std::ignore = SerializeState(state); });

        state.InstallIntent.FixedVhd = false;
        state.InstallIntent.Location = L"C:\\WSL\\Dev\\..\\Other";
        VerifyInvalidState([&]() { std::ignore = SerializeState(state); });

        state.InstallIntent.Location.reset();
        state.InstallIntent.Selector = DistributionSelector::Default;
        VerifyInvalidState([&]() { std::ignore = SerializeState(state); });
    }

    TEST_METHOD(RejectUnknownDuplicateAndMalformedState)
    {
        const auto state =
            MakeState(ParseGuid(L"{11111111-1111-1111-1111-111111111111}"), ParseGuid(L"{22222222-2222-2222-2222-222222222222}"));
        const auto serialized = SerializeState(state);

        auto unknown = serialized;
        unknown.insert(1, L"\"unknown\":1,");
        VERIFY_IS_TRUE(DecodeState(MakeStringValue(unknown)).Kind == StateValueKind::Corrupt);

        auto duplicate = serialized;
        duplicate.insert(1, L"\"schemaVersion\":1,");
        VERIFY_IS_TRUE(DecodeState(MakeStringValue(duplicate)).Kind == StateValueKind::Corrupt);

        auto nestedDuplicate = serialized;
        const auto intent = nestedDuplicate.find(L"\"intent\":{");
        VERIFY_IS_TRUE(intent != nestedDuplicate.npos);
        nestedDuplicate.insert(intent + std::size(L"\"intent\":{") - 1, L"\"selector\":\"explicit\",");
        VERIFY_IS_TRUE(DecodeState(MakeStringValue(nestedDuplicate)).Kind == StateValueKind::Corrupt);

        auto wrongType = MakeStringValue(serialized);
        wrongType.Type = REG_BINARY;
        VERIFY_IS_TRUE(DecodeState(wrongType).Kind == StateValueKind::Corrupt);

        auto missingTerminator = MakeStringValue(serialized);
        missingTerminator.Data.resize(missingTerminator.Data.size() - sizeof(WCHAR));
        missingTerminator.Size = gsl::narrow_cast<DWORD>(missingTerminator.Data.size());
        VERIFY_IS_TRUE(DecodeState(missingTerminator).Kind == StateValueKind::Corrupt);

        auto embeddedNull = MakeStringValue(serialized + std::wstring{L'\0'} + L"ignored");
        VERIFY_IS_TRUE(DecodeState(embeddedNull).Kind == StateValueKind::Corrupt);
    }

    TEST_METHOD(RejectInvalidUtf16)
    {
        auto serialized = SerializeState(
            MakeState(ParseGuid(L"{11111111-1111-1111-1111-111111111111}"), ParseGuid(L"{22222222-2222-2222-2222-222222222222}")));
        const auto writerVersion = serialized.find(L"1.2.3");
        VERIFY_IS_TRUE(writerVersion != serialized.npos);
        serialized[writerVersion] = static_cast<wchar_t>(0xD800);

        VERIFY_IS_TRUE(DecodeState(MakeStringValue(serialized)).Kind == StateValueKind::Corrupt);
    }

    TEST_METHOD(PreserveForwardSchema)
    {
        auto serialized = SerializeState(
            MakeState(ParseGuid(L"{11111111-1111-1111-1111-111111111111}"), ParseGuid(L"{22222222-2222-2222-2222-222222222222}")));
        const auto schema = serialized.find(L"\"schemaVersion\":1");
        VERIFY_IS_TRUE(schema != serialized.npos);
        serialized.replace(schema, wcslen(L"\"schemaVersion\":1"), L"\"schemaVersion\":2");
        serialized.insert(1, L"\"futureField\":{\"value\":true},");

        const auto decoded = DecodeState(MakeStringValue(serialized));
        VERIFY_IS_TRUE(decoded.Kind == StateValueKind::Unsupported);
        VERIFY_ARE_EQUAL(2u, decoded.UnsupportedVersion.value());
        VERIFY_IS_TRUE(decoded.Raw.has_value());
    }

    TEST_METHOD(EvaluateTriggerRecoveryMatrix)
    {
        const auto generation1 = ParseGuid(L"{11111111-1111-1111-1111-111111111111}");
        const auto generation2 = ParseGuid(L"{22222222-2222-2222-2222-222222222222}");
        const auto bootId = ParseGuid(L"{33333333-3333-3333-3333-333333333333}");
        const auto state1 = DecodeState(MakeStringValue(SerializeState(MakeState(generation1, bootId))));
        const auto state2 = DecodeState(MakeStringValue(SerializeState(MakeState(generation2, bootId))));
        const auto trigger1 = DecodeTrigger(MakeStringValue(BuildRunCommand(L"C:\\WSL\\wsl.exe", generation1)));
        const auto trigger2 = DecodeTrigger(MakeStringValue(BuildRunCommand(L"C:\\WSL\\wsl.exe", generation2)));

        VERIFY_IS_TRUE(EvaluateAutomaticRecovery(state1, trigger1, generation1).Action == RecoveryAction::Run);
        VERIFY_IS_TRUE(EvaluateAutomaticRecovery(state1, TriggerValue{}, generation1).Action == RecoveryAction::Quiet);
        VERIFY_IS_TRUE(EvaluateAutomaticRecovery(StateValue{}, trigger1, generation1).Action == RecoveryAction::ClearOrphanTrigger);
        VERIFY_IS_TRUE(EvaluateAutomaticRecovery(state2, trigger1, generation1).Action == RecoveryAction::DisarmTrigger);
        VERIFY_IS_TRUE(EvaluateAutomaticRecovery(state2, trigger2, generation1).Action == RecoveryAction::Quiet);
        VERIFY_IS_TRUE(EvaluateAutomaticRecovery(state2, trigger2, generation2).Action == RecoveryAction::Run);
    }

    TEST_METHOD(RecoverInterruptedSupersedeWrites)
    {
        const auto generation1 = ParseGuid(L"{11111111-1111-1111-1111-111111111111}");
        const auto generation2 = ParseGuid(L"{22222222-2222-2222-2222-222222222222}");
        const auto bootId = ParseGuid(L"{33333333-3333-3333-3333-333333333333}");
        const auto state1 = MakeState(generation1, bootId);
        const auto state2 = MakeState(generation2, bootId);

        MemoryStore store;
        store.WriteState(SerializeState(state1));
        store.WriteTrigger(BuildRunCommand(L"C:\\WSL\\wsl.exe", generation1));
        VERIFY_IS_TRUE(
            EvaluateAutomaticRecovery(DecodeState(store.ReadState()), DecodeTrigger(store.ReadTrigger()), generation1).Action ==
            RecoveryAction::Run);

        store.DeleteTrigger();
        VERIFY_IS_TRUE(
            EvaluateAutomaticRecovery(DecodeState(store.ReadState()), DecodeTrigger(store.ReadTrigger()), generation1).Action ==
            RecoveryAction::Quiet);

        store.DeleteState();
        store.WriteState(SerializeState(state2));
        VERIFY_IS_TRUE(
            EvaluateAutomaticRecovery(DecodeState(store.ReadState()), DecodeTrigger(store.ReadTrigger()), generation1).Action ==
            RecoveryAction::Quiet);

        store.WriteTrigger(BuildRunCommand(L"C:\\WSL\\wsl.exe", generation2));
        VERIFY_IS_TRUE(
            EvaluateAutomaticRecovery(DecodeState(store.ReadState()), DecodeTrigger(store.ReadTrigger()), generation1).Action ==
            RecoveryAction::Quiet);
        VERIFY_IS_TRUE(
            EvaluateAutomaticRecovery(DecodeState(store.ReadState()), DecodeTrigger(store.ReadTrigger()), generation2).Action ==
            RecoveryAction::Run);

        store.DeleteState();
        VERIFY_IS_TRUE(
            EvaluateAutomaticRecovery(DecodeState(store.ReadState()), DecodeTrigger(store.ReadTrigger()), generation2).Action ==
            RecoveryAction::ClearOrphanTrigger);
    }

    TEST_METHOD(QuarantineCorruptCurrentState)
    {
        const auto generation = ParseGuid(L"{11111111-1111-1111-1111-111111111111}");
        auto corrupt = MakeStringValue(L"{\"schemaVersion\":1}");
        const auto state = DecodeState(corrupt);
        const auto trigger = DecodeTrigger(MakeStringValue(BuildRunCommand(L"C:\\WSL\\wsl.exe", generation)));

        VERIFY_IS_TRUE(state.Kind == StateValueKind::Corrupt);
        VERIFY_IS_TRUE(EvaluateAutomaticRecovery(state, trigger, generation).Action == RecoveryAction::QuarantineState);
    }

    TEST_METHOD(EnforceAutomaticAttemptBudget)
    {
        const auto initialBoot = ParseGuid(L"{11111111-1111-1111-1111-111111111111}");
        auto state = MakeState(ParseGuid(L"{22222222-2222-2222-2222-222222222222}"), initialBoot);
        VERIFY_IS_TRUE(EvaluateAutomaticAttempt(state, initialBoot) == AttemptAction::SameBoot);

        const std::array boots{
            ParseGuid(L"{30000000-0000-0000-0000-000000000001}"),
            ParseGuid(L"{30000000-0000-0000-0000-000000000002}"),
            ParseGuid(L"{30000000-0000-0000-0000-000000000003}"),
            ParseGuid(L"{30000000-0000-0000-0000-000000000004}")};
        for (const auto& boot : boots)
        {
            VERIFY_IS_TRUE(EvaluateAutomaticAttempt(state, boot) == AttemptAction::Start);
            ReserveAutomaticAttempt(state, boot);
            VERIFY_IS_TRUE(state.AttemptInProgress);
            CompleteAutomaticAttempt(state);
        }

        VERIFY_ARE_EQUAL(c_maxAutomaticAttempts, state.AutomaticAttempts);
        VERIFY_IS_TRUE(EvaluateAutomaticAttempt(state, ParseGuid(L"{40000000-0000-0000-0000-000000000000}")) == AttemptAction::Exhausted);

        state.CurrentPhase = Phase::DistributionCommitted;
        state.DistroRegistration.Status = RegistrationStatus::Committed;
        state.DistroRegistration.DistributionName = L"Ubuntu";
        state.DistroRegistration.TargetName = L"Ubuntu";
        state.DistroRegistration.InstalledName = L"Ubuntu";
        state.DistroRegistration.CommittedId = ParseGuid(L"{50000000-0000-0000-0000-000000000000}");
        VERIFY_IS_TRUE(EvaluateAutomaticAttempt(state, ParseGuid(L"{60000000-0000-0000-0000-000000000000}")) == AttemptAction::CompleteCommitted);
    }

    TEST_METHOD(CancelDoesNotConsumeAttempt)
    {
        const auto initialBoot = ParseGuid(L"{11111111-1111-1111-1111-111111111111}");
        const auto retryBoot = ParseGuid(L"{22222222-2222-2222-2222-222222222222}");
        auto state = MakeState(ParseGuid(L"{33333333-3333-3333-3333-333333333333}"), initialBoot);

        ReserveAutomaticAttempt(state, retryBoot);
        CancelAutomaticAttempt(state);
        VERIFY_ARE_EQUAL(0u, state.AutomaticAttempts);
        VERIFY_IS_FALSE(state.AttemptInProgress);
        VERIFY_IS_TRUE(EvaluateAutomaticAttempt(state, retryBoot) == AttemptAction::SameBoot);
    }

    TEST_METHOD(PreserveCrashReservation)
    {
        const auto initialBoot = ParseGuid(L"{11111111-1111-1111-1111-111111111111}");
        const auto firstWorkBoot = ParseGuid(L"{22222222-2222-2222-2222-222222222222}");
        const auto nextBoot = ParseGuid(L"{33333333-3333-3333-3333-333333333333}");
        auto state = MakeState(ParseGuid(L"{44444444-4444-4444-4444-444444444444}"), initialBoot);

        ReserveAutomaticAttempt(state, firstWorkBoot);
        VERIFY_ARE_EQUAL(1u, state.AutomaticAttempts);
        VERIFY_IS_TRUE(EvaluateAutomaticAttempt(state, firstWorkBoot) == AttemptAction::SameBoot);
        VERIFY_IS_TRUE(EvaluateAutomaticAttempt(state, nextBoot) == AttemptAction::Start);
        ReserveAutomaticAttempt(state, nextBoot);
        VERIFY_ARE_EQUAL(2u, state.AutomaticAttempts);
    }

    TEST_METHOD(QuoteAndParseRunCommand)
    {
        const auto generation = ParseGuid(L"{11111111-1111-1111-1111-111111111111}");
        const auto command = BuildRunCommand(L"C:\\Program Files\\WSL\\wsl.exe", generation);
        const auto parsed = ParseRunCommand(command);

        VERIFY_IS_TRUE(parsed.has_value());
        VERIFY_IS_TRUE(AreEqual(generation, *parsed));
        VERIFY_IS_TRUE(ParseRunCommand(command + L" --unexpected") == std::nullopt);
    }

    TEST_METHOD(EnforceRunCommandLimit)
    {
        const auto generation = ParseGuid(L"{11111111-1111-1111-1111-111111111111}");
        const auto shortCommand = BuildRunCommand(L"C:\\x", generation);
        const auto fixedCharacters = shortCommand.size() - 4;
        const auto exactLauncherLength = c_maxRunCommandCharacters - fixedCharacters;
        const auto exactLauncher = std::wstring{L"C:\\"} + std::wstring(exactLauncherLength - 3, L'a');

        VERIFY_ARE_EQUAL(c_maxRunCommandCharacters, BuildRunCommand(exactLauncher, generation).size());
        VERIFY_ARE_EQUAL(HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW), wil::ResultFromException([&]() {
                             std::ignore = BuildRunCommand(exactLauncher + L"a", generation);
                         }));
    }

    TEST_METHOD(QuoteWindowsArgumentsRoundTrip)
    {
        const std::array<std::wstring, 5> expected{L"", L"plain", L"with space", L"trailing\\", L"embedded\"quote"};
        std::wstring command = L"test.exe";
        for (const auto& argument : expected)
        {
            command += L' ';
            command += wsl::shared::string::QuoteWindowsCommandLineArgument<wchar_t>(argument);
        }

        int argumentCount{};
        const wil::unique_hlocal_ptr<LPWSTR[]> arguments{CommandLineToArgvW(command.c_str(), &argumentCount)};
        VERIFY_ARE_EQUAL(gsl::narrow_cast<int>(expected.size() + 1), argumentCount);
        for (size_t index = 0; index < expected.size(); ++index)
        {
            VERIFY_ARE_EQUAL(expected[index], std::wstring{arguments[index + 1]});
        }
    }

    TEST_METHOD(ClassifyMutexWaits)
    {
        VERIFY_IS_TRUE(ClassifyMutexWaitResult(WAIT_OBJECT_0) == MutexAcquireResult::Acquired);
        VERIFY_IS_TRUE(ClassifyMutexWaitResult(WAIT_ABANDONED) == MutexAcquireResult::Abandoned);
        VERIFY_IS_TRUE(ClassifyMutexWaitResult(WAIT_TIMEOUT) == MutexAcquireResult::Timeout);
    }

    TEST_METHOD(SerializeMutexAccess)
    {
        ScopedMutex owner(0);
        VERIFY_IS_TRUE(owner.Result() == MutexAcquireResult::Acquired || owner.Result() == MutexAcquireResult::Abandoned);

        auto contenderResult = MutexAcquireResult::Acquired;
        std::thread contender([&]() {
            ScopedMutex mutex(50);
            contenderResult = mutex.Result();
        });
        contender.join();
        VERIFY_IS_TRUE(contenderResult == MutexAcquireResult::Timeout);

        owner.Release();
        ScopedMutex successor(1'000);
        VERIFY_IS_TRUE(successor.Result() == MutexAcquireResult::Acquired || successor.Result() == MutexAcquireResult::Abandoned);
    }

    TEST_METHOD(RequireUnambiguousRetryPath)
    {
        VERIFY_IS_FALSE(IsRetryPathSafe(std::nullopt));

        const auto root =
            std::filesystem::temp_directory_path() / std::format(L"wsl-install-resume-{}", GuidToString(CreateGeneration()));
        auto cleanup = wil::scope_exit_log(WI_DIAGNOSTICS_INFO, [&]() { std::filesystem::remove_all(root); });

        VERIFY_IS_TRUE(IsRetryPathSafe(root.wstring()));
        std::filesystem::create_directories(root);
        VERIFY_IS_TRUE(IsRetryPathSafe(root.wstring()));

        std::ofstream{root / L"ext4.vhdx"} << "data";
        VERIFY_IS_FALSE(IsRetryPathSafe(root.wstring()));
    }
};
