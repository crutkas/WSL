// Copyright (C) Microsoft Corporation. All rights reserved.

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <wil/resource.h>
#include "defs.h"

namespace wsl::windows::common::installresume {

inline constexpr unsigned int c_schemaVersion = 1;
inline constexpr unsigned int c_maxAutomaticAttempts = 4;
inline constexpr DWORD c_mutexWaitMilliseconds = 30'000;
inline constexpr size_t c_maxStateCharacters = 32 * 1024;
inline constexpr size_t c_maxRunCommandCharacters = 260;

enum class DistributionSelector
{
    Default,
    Explicit
};

enum class Phase
{
    AwaitingPrerequisites,
    InstallingDistribution,
    DistributionCommitted
};

enum class RegistrationStatus
{
    None,
    Prepared,
    Started,
    Committed
};

struct Intent
{
    DistributionSelector Selector{DistributionSelector::Default};
    std::optional<std::wstring> Distribution;
    std::optional<std::wstring> Name;
    std::optional<std::wstring> Location;
    std::optional<ULONG> Version;
    std::optional<uint64_t> VhdSize;
    bool FixedVhd{};
    bool Legacy{};
    bool WebDownload{};
    bool EnableWsl1{};
    bool NoLaunch{};
};

struct Registration
{
    RegistrationStatus Status{RegistrationStatus::None};
    std::optional<std::wstring> DistributionName;
    std::optional<std::wstring> TargetName;
    std::optional<std::wstring> InstalledName;
    std::optional<GUID> CommittedId;
};

struct State
{
    GUID Generation{};
    std::wstring WriterVersion;
    Phase CurrentPhase{Phase::AwaitingPrerequisites};
    GUID LastAutomaticBootId{};
    unsigned int AutomaticAttempts{};
    bool AttemptInProgress{};
    Intent InstallIntent;
    Registration DistroRegistration;
};

struct RawRegistryValue
{
    DWORD Type{};
    DWORD Size{};
    bool Oversized{};
    std::vector<BYTE> Data;
};

enum class StateValueKind
{
    Missing,
    Valid,
    Unsupported,
    Corrupt
};

struct StateValue
{
    StateValueKind Kind{StateValueKind::Missing};
    std::optional<State> Value;
    std::optional<unsigned int> UnsupportedVersion;
    std::optional<RawRegistryValue> Raw;
};

enum class TriggerValueKind
{
    Missing,
    Valid,
    Corrupt
};

struct TriggerValue
{
    TriggerValueKind Kind{TriggerValueKind::Missing};
    std::optional<GUID> Generation;
    std::optional<RawRegistryValue> Raw;
};

enum class RecoveryAction
{
    Run,
    Quiet,
    ClearOrphanTrigger,
    DisarmTrigger,
    QuarantineState,
    ReportUnsupported
};

struct RecoveryDecision
{
    RecoveryAction Action{RecoveryAction::Quiet};
    bool VisibleFailure{};
};

enum class AttemptAction
{
    Start,
    SameBoot,
    CompleteCommitted,
    Exhausted
};

enum class MutexAcquireResult
{
    Acquired,
    Abandoned,
    Timeout
};

class Store
{
public:
    virtual ~Store() = default;

    virtual std::optional<RawRegistryValue> ReadState() const = 0;
    virtual std::optional<RawRegistryValue> ReadTrigger() const = 0;
    virtual void Arm(std::wstring_view state, std::wstring_view trigger) = 0;
    virtual void WriteState(std::wstring_view value) = 0;
    virtual void WriteTrigger(std::wstring_view value) = 0;
    virtual void DeleteState() = 0;
    virtual void DeleteTrigger() = 0;
    virtual void QuarantineState(std::wstring_view reason) = 0;
};

class RegistryStore final : public Store
{
public:
    RegistryStore();

    std::optional<RawRegistryValue> ReadState() const override;
    std::optional<RawRegistryValue> ReadTrigger() const override;
    void Arm(std::wstring_view state, std::wstring_view trigger) override;
    void WriteState(std::wstring_view value) override;
    void WriteTrigger(std::wstring_view value) override;
    void DeleteState() override;
    void DeleteTrigger() override;
    void QuarantineState(std::wstring_view reason) override;

private:
    wil::unique_hkey m_currentUserKey;
    wil::unique_hkey m_lxssKey;
    wil::unique_hkey m_resumeKey;
    wil::unique_hkey m_runKey;
};

class ScopedMutex
{
public:
    explicit ScopedMutex(DWORD timeoutMilliseconds = c_mutexWaitMilliseconds);
    ~ScopedMutex();

    NON_COPYABLE(ScopedMutex);
    NON_MOVABLE(ScopedMutex);

    MutexAcquireResult Result() const noexcept;
    void Release();

private:
    wil::unique_handle m_mutex;
    MutexAcquireResult m_result{MutexAcquireResult::Timeout};
    bool m_owned{};
};

bool AreEqual(const GUID& first, const GUID& second) noexcept;
std::wstring GuidToString(const GUID& value);
std::optional<GUID> GuidFromString(std::wstring_view value);
GUID CreateGeneration();
GUID GetCurrentBootId();

std::wstring CanonicalizeLocation(std::wstring_view value);
void ValidateIntent(const Intent& intent);
void ValidateState(const State& state);

std::wstring SerializeState(const State& state);
StateValue DecodeState(const std::optional<RawRegistryValue>& value);
TriggerValue DecodeTrigger(const std::optional<RawRegistryValue>& value);

std::wstring GetStableLauncherPath();
std::wstring BuildRunCommand(std::wstring_view launcher, const GUID& generation);
std::optional<GUID> ParseRunCommand(std::wstring_view command);
std::wstring BuildMutexName(PSID userSid);
MutexAcquireResult ClassifyMutexWaitResult(DWORD waitResult);

RecoveryDecision EvaluateAutomaticRecovery(const StateValue& state, const TriggerValue& trigger, const GUID& runnerGeneration);
AttemptAction EvaluateAutomaticAttempt(const State& state, const GUID& currentBootId);
void ReserveAutomaticAttempt(State& state, const GUID& currentBootId);
void CompleteAutomaticAttempt(State& state);
void CancelAutomaticAttempt(State& state);

bool IsRetryPathSafe(const std::optional<std::wstring>& location);

} // namespace wsl::windows::common::installresume
