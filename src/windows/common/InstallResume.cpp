// Copyright (C) Microsoft Corporation. All rights reserved.

#include "precomp.h"
#include "InstallResume.h"

#include <nlohmann/json.hpp>

using nlohmann::json;

namespace {

constexpr auto c_runRegistryPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr auto c_resumeKeyName = L"InstallResume";
constexpr auto c_quarantineKeyName = L"InstallResumeQuarantine";
constexpr auto c_stateValueName = L"State";
constexpr auto c_triggerValueName = L"WSLInstallResume";
constexpr auto c_quarantineReasonValueName = L"QuarantineReason";
constexpr ULONG c_systemBootEnvironmentInformation = 90;
constexpr unsigned int c_namespaceOpenAttempts = 4;

struct BootEnvironmentInformation
{
    GUID BootIdentifier;
    ULONG FirmwareType;
    ULONGLONG BootFlags;
};

using NtQuerySystemInformationRoutine = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

class ProcessPrivateNamespace
{
public:
    ProcessPrivateNamespace(SECURITY_ATTRIBUTES* attributes, HANDLE boundaryDescriptor, std::wstring_view name)
    {
        const std::wstring nullTerminatedName{name};
        for (unsigned int attempt = 0; attempt < c_namespaceOpenAttempts; ++attempt)
        {
            m_handle = CreatePrivateNamespaceW(attributes, boundaryDescriptor, nullTerminatedName.c_str());
            if (m_handle != nullptr)
            {
                return;
            }

            const auto createError = GetLastError();
            THROW_WIN32_IF(createError, createError != ERROR_ALREADY_EXISTS);
            m_handle = OpenPrivateNamespaceW(boundaryDescriptor, nullTerminatedName.c_str());
            if (m_handle != nullptr)
            {
                return;
            }

            const auto openError = GetLastError();
            THROW_WIN32_IF(openError, openError != ERROR_FILE_NOT_FOUND && openError != ERROR_PATH_NOT_FOUND);
        }

        THROW_WIN32(ERROR_RETRY);
    }

    ~ProcessPrivateNamespace()
    {
        LOG_LAST_ERROR_IF(!ClosePrivateNamespace(m_handle, 0));
    }

    NON_COPYABLE(ProcessPrivateNamespace);
    NON_MOVABLE(ProcessPrivateNamespace);

private:
    HANDLE m_handle{};
};

void EnsureProcessPrivateNamespace(SECURITY_ATTRIBUTES* attributes, HANDLE boundaryDescriptor, std::wstring_view name)
{
    static ProcessPrivateNamespace privateNamespace{attributes, boundaryDescriptor, name};
}

bool IsNullGuid(const GUID& value)
{
    return wsl::windows::common::installresume::AreEqual(value, GUID{});
}

std::string WideToUtf8(std::wstring_view value)
{
    if (value.empty())
    {
        return {};
    }

    THROW_HR_IF(E_INVALIDARG, value.size() > INT_MAX);
    const auto size =
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    THROW_LAST_ERROR_IF(size == 0);

    std::string result(size, '\0');
    THROW_LAST_ERROR_IF(
        WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), static_cast<int>(result.size()), nullptr, nullptr) ==
        0);
    return result;
}

std::wstring Utf8ToWide(std::string_view value)
{
    if (value.empty())
    {
        return {};
    }

    THROW_HR_IF(E_INVALIDARG, value.size() > INT_MAX);
    const auto size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    THROW_LAST_ERROR_IF(size == 0);

    std::wstring result(size, L'\0');
    THROW_LAST_ERROR_IF(
        MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), static_cast<int>(result.size())) == 0);
    return result;
}

std::optional<std::wstring> DecodeRegistryString(const wsl::windows::common::installresume::RawRegistryValue& value, size_t maximumCharacters)
{
    if (value.Type != REG_SZ || value.Oversized || value.Size != value.Data.size() || value.Size < sizeof(WCHAR) ||
        (value.Size % sizeof(WCHAR)) != 0)
    {
        return {};
    }

    std::wstring result(value.Size / sizeof(WCHAR), L'\0');
    memcpy(result.data(), value.Data.data(), value.Size);
    if (result.back() != L'\0' || result.size() - 1 > maximumCharacters)
    {
        return {};
    }

    if (std::find(result.begin(), result.end() - 1, L'\0') != result.end() - 1)
    {
        return {};
    }

    result.pop_back();
    return result;
}

std::optional<wsl::windows::common::installresume::RawRegistryValue> ReadRawRegistryValue(HKEY key, LPCWSTR valueName, size_t maximumBytes)
{
    DWORD type{};
    DWORD size{};
    auto result = RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &size);
    if (result == ERROR_FILE_NOT_FOUND)
    {
        return {};
    }

    THROW_IF_WIN32_ERROR(result);

    wsl::windows::common::installresume::RawRegistryValue value;
    value.Type = type;
    value.Size = size;
    value.Oversized = size > maximumBytes;
    if (value.Oversized)
    {
        return value;
    }

    value.Data.resize(size);
    result = RegQueryValueExW(key, valueName, nullptr, &type, value.Data.data(), &size);
    THROW_IF_WIN32_ERROR(result);
    value.Type = type;
    value.Size = size;
    value.Data.resize(size);
    return value;
}

void WriteRegistryString(HKEY key, LPCWSTR valueName, std::wstring_view value, size_t maximumCharacters)
{
    THROW_HR_IF(E_INVALIDARG, value.size() > maximumCharacters || value.find(L'\0') != value.npos);

    size_t byteCount{};
    THROW_IF_FAILED(SizeTAdd(value.size(), 1, &byteCount));
    THROW_IF_FAILED(SizeTMult(byteCount, sizeof(WCHAR), &byteCount));
    THROW_HR_IF(E_INVALIDARG, byteCount > DWORD_MAX);
    const std::wstring nullTerminated{value};
    THROW_IF_WIN32_ERROR(RegSetValueExW(
        key, valueName, 0, REG_SZ, reinterpret_cast<const BYTE*>(nullTerminated.c_str()), static_cast<DWORD>(byteCount)));
}

void DeleteRegistryValue(HKEY key, LPCWSTR valueName)
{
    const auto result = RegDeleteValueW(key, valueName);
    THROW_WIN32_IF(result, result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND);
}

json ParseJson(std::wstring_view value)
{
    std::vector<std::unordered_set<std::string>> objectKeys;
    const auto callback = [&](int, json::parse_event_t event, json& parsed) {
        if (event == json::parse_event_t::object_start)
        {
            objectKeys.emplace_back();
        }
        else if (event == json::parse_event_t::key)
        {
            THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), objectKeys.empty());
            THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_DUP_NAME), !objectKeys.back().insert(parsed.get<std::string>()).second);
        }
        else if (event == json::parse_event_t::object_end)
        {
            THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), objectKeys.empty());
            objectKeys.pop_back();
        }

        return true;
    };

    return json::parse(WideToUtf8(value), callback, true, false);
}

void RequireKeys(const json& value, std::initializer_list<std::string_view> keys)
{
    THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !value.is_object() || value.size() != keys.size());
    for (const auto key : keys)
    {
        THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !value.contains(key));
    }
}

uint64_t ReadUnsigned(const json& value)
{
    THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !value.is_number_unsigned() && !value.is_number_integer());
    if (value.is_number_integer())
    {
        const auto signedValue = value.get<int64_t>();
        THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), signedValue < 0);
        return static_cast<uint64_t>(signedValue);
    }

    return value.get<uint64_t>();
}

bool ReadBoolean(const json& value)
{
    THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !value.is_boolean());
    return value.get<bool>();
}

std::wstring ReadString(const json& value)
{
    THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !value.is_string());
    return Utf8ToWide(value.get<std::string>());
}

std::optional<std::wstring> ReadOptionalString(const json& value)
{
    if (value.is_null())
    {
        return {};
    }

    return ReadString(value);
}

std::optional<uint64_t> ReadOptionalUnsigned(const json& value)
{
    if (value.is_null())
    {
        return {};
    }

    return ReadUnsigned(value);
}

std::optional<GUID> ReadOptionalGuid(const json& value)
{
    if (value.is_null())
    {
        return {};
    }

    auto guid = wsl::windows::common::installresume::GuidFromString(ReadString(value));
    THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !guid.has_value());
    return guid;
}

json WriteOptionalString(const std::optional<std::wstring>& value)
{
    return value.has_value() ? json(WideToUtf8(*value)) : json(nullptr);
}

json WriteOptionalUnsigned(const std::optional<uint64_t>& value)
{
    return value.has_value() ? json(*value) : json(nullptr);
}

json WriteOptionalGuid(const std::optional<GUID>& value)
{
    return value.has_value() ? json(WideToUtf8(wsl::windows::common::installresume::GuidToString(*value))) : json(nullptr);
}

std::string_view ToString(wsl::windows::common::installresume::DistributionSelector value)
{
    using wsl::windows::common::installresume::DistributionSelector;
    switch (value)
    {
    case DistributionSelector::Default:
        return "default";
    case DistributionSelector::Explicit:
        return "explicit";
    default:
        THROW_HR(E_UNEXPECTED);
    }
}

std::string_view ToString(wsl::windows::common::installresume::Phase value)
{
    using wsl::windows::common::installresume::Phase;
    switch (value)
    {
    case Phase::AwaitingPrerequisites:
        return "awaitingPrerequisites";
    case Phase::InstallingDistribution:
        return "installingDistribution";
    case Phase::DistributionCommitted:
        return "distributionCommitted";
    default:
        THROW_HR(E_UNEXPECTED);
    }
}

std::string_view ToString(wsl::windows::common::installresume::RegistrationStatus value)
{
    using wsl::windows::common::installresume::RegistrationStatus;
    switch (value)
    {
    case RegistrationStatus::None:
        return "none";
    case RegistrationStatus::Prepared:
        return "prepared";
    case RegistrationStatus::Started:
        return "started";
    case RegistrationStatus::Committed:
        return "committed";
    default:
        THROW_HR(E_UNEXPECTED);
    }
}

wsl::windows::common::installresume::DistributionSelector ReadSelector(const json& value)
{
    const auto stringValue = ReadString(value);
    if (stringValue == L"default")
    {
        return wsl::windows::common::installresume::DistributionSelector::Default;
    }
    if (stringValue == L"explicit")
    {
        return wsl::windows::common::installresume::DistributionSelector::Explicit;
    }

    THROW_HR(HRESULT_FROM_WIN32(ERROR_INVALID_DATA));
}

wsl::windows::common::installresume::Phase ReadPhase(const json& value)
{
    const auto stringValue = ReadString(value);
    if (stringValue == L"awaitingPrerequisites")
    {
        return wsl::windows::common::installresume::Phase::AwaitingPrerequisites;
    }
    if (stringValue == L"installingDistribution")
    {
        return wsl::windows::common::installresume::Phase::InstallingDistribution;
    }
    if (stringValue == L"distributionCommitted")
    {
        return wsl::windows::common::installresume::Phase::DistributionCommitted;
    }

    THROW_HR(HRESULT_FROM_WIN32(ERROR_INVALID_DATA));
}

wsl::windows::common::installresume::RegistrationStatus ReadRegistrationStatus(const json& value)
{
    const auto stringValue = ReadString(value);
    if (stringValue == L"none")
    {
        return wsl::windows::common::installresume::RegistrationStatus::None;
    }
    if (stringValue == L"prepared")
    {
        return wsl::windows::common::installresume::RegistrationStatus::Prepared;
    }
    if (stringValue == L"started")
    {
        return wsl::windows::common::installresume::RegistrationStatus::Started;
    }
    if (stringValue == L"committed")
    {
        return wsl::windows::common::installresume::RegistrationStatus::Committed;
    }

    THROW_HR(HRESULT_FROM_WIN32(ERROR_INVALID_DATA));
}

void ValidateString(const std::optional<std::wstring>& value, size_t maximumCharacters)
{
    if (value.has_value())
    {
        THROW_HR_IF(
            HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
            value->empty() || value->size() > maximumCharacters || value->find(L'\0') != value->npos);
    }
}

wsl::windows::common::installresume::State ParseState(const json& root)
{
    using namespace wsl::windows::common::installresume;

    RequireKeys(
        root,
        {"schemaVersion",
         "writerVersion",
         "generation",
         "phase",
         "lastAutomaticBootId",
         "automaticAttempts",
         "attemptInProgress",
         "intent",
         "registration"});
    THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), ReadUnsigned(root.at("schemaVersion")) != c_schemaVersion);

    State state;
    state.WriterVersion = ReadString(root.at("writerVersion"));
    state.Generation = ReadOptionalGuid(root.at("generation")).value_or(GUID{});
    state.CurrentPhase = ReadPhase(root.at("phase"));
    state.LastAutomaticBootId = ReadOptionalGuid(root.at("lastAutomaticBootId")).value_or(GUID{});
    const auto automaticAttempts = ReadUnsigned(root.at("automaticAttempts"));
    THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), automaticAttempts > UINT_MAX);
    state.AutomaticAttempts = static_cast<unsigned int>(automaticAttempts);
    state.AttemptInProgress = ReadBoolean(root.at("attemptInProgress"));

    const auto& intent = root.at("intent");
    RequireKeys(
        intent,
        {"selector",
         "distribution",
         "name",
         "location",
         "version",
         "vhdSize",
         "fixedVhd",
         "legacy",
         "webDownload",
         "enableWsl1",
         "noLaunch"});
    state.InstallIntent.Selector = ReadSelector(intent.at("selector"));
    state.InstallIntent.Distribution = ReadOptionalString(intent.at("distribution"));
    state.InstallIntent.Name = ReadOptionalString(intent.at("name"));
    state.InstallIntent.Location = ReadOptionalString(intent.at("location"));
    if (const auto version = ReadOptionalUnsigned(intent.at("version")))
    {
        THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), *version > ULONG_MAX);
        state.InstallIntent.Version = static_cast<ULONG>(*version);
    }
    state.InstallIntent.VhdSize = ReadOptionalUnsigned(intent.at("vhdSize"));
    state.InstallIntent.FixedVhd = ReadBoolean(intent.at("fixedVhd"));
    state.InstallIntent.Legacy = ReadBoolean(intent.at("legacy"));
    state.InstallIntent.WebDownload = ReadBoolean(intent.at("webDownload"));
    state.InstallIntent.EnableWsl1 = ReadBoolean(intent.at("enableWsl1"));
    state.InstallIntent.NoLaunch = ReadBoolean(intent.at("noLaunch"));

    const auto& registration = root.at("registration");
    RequireKeys(registration, {"status", "distributionName", "targetName", "installedName", "committedId"});
    state.DistroRegistration.Status = ReadRegistrationStatus(registration.at("status"));
    state.DistroRegistration.DistributionName = ReadOptionalString(registration.at("distributionName"));
    state.DistroRegistration.TargetName = ReadOptionalString(registration.at("targetName"));
    state.DistroRegistration.InstalledName = ReadOptionalString(registration.at("installedName"));
    state.DistroRegistration.CommittedId = ReadOptionalGuid(registration.at("committedId"));

    ValidateState(state);
    return state;
}

} // namespace

bool wsl::windows::common::installresume::AreEqual(const GUID& first, const GUID& second) noexcept
{
    return InlineIsEqualGUID(first, second);
}

std::wstring wsl::windows::common::installresume::GuidToString(const GUID& value)
{
    return wsl::shared::string::GuidToString<wchar_t>(value);
}

std::optional<GUID> wsl::windows::common::installresume::GuidFromString(std::wstring_view value)
{
    const auto parsed = wsl::shared::string::ToGuid(value);
    if (!parsed.has_value() || GuidToString(*parsed) != value)
    {
        return {};
    }

    return parsed;
}

GUID wsl::windows::common::installresume::CreateGeneration()
{
    GUID value{};
    THROW_IF_FAILED(CoCreateGuid(&value));
    return value;
}

GUID wsl::windows::common::installresume::GetCurrentBootId()
{
    const auto module = GetModuleHandleW(L"ntdll.dll");
    THROW_LAST_ERROR_IF(module == nullptr);

    const auto querySystemInformation =
        reinterpret_cast<NtQuerySystemInformationRoutine>(GetProcAddress(module, "NtQuerySystemInformation"));
    THROW_LAST_ERROR_IF(querySystemInformation == nullptr);

    BootEnvironmentInformation information{};
    THROW_IF_NTSTATUS_FAILED(querySystemInformation(c_systemBootEnvironmentInformation, &information, sizeof(information), nullptr));
    THROW_HR_IF(E_UNEXPECTED, IsNullGuid(information.BootIdentifier));
    return information.BootIdentifier;
}

std::wstring wsl::windows::common::installresume::CanonicalizeLocation(std::wstring_view value)
{
    THROW_HR_IF(E_INVALIDARG, value.empty() || value.find(L'\0') != value.npos);

    const std::wstring nullTerminated{value};
    THROW_HR_IF(E_INVALIDARG, PathIsRelativeW(nullTerminated.c_str()));

    const auto required = GetFullPathNameW(nullTerminated.c_str(), 0, nullptr, nullptr);
    THROW_LAST_ERROR_IF(required == 0);

    std::wstring fullPath(required, L'\0');
    const auto written = GetFullPathNameW(nullTerminated.c_str(), required, fullPath.data(), nullptr);
    THROW_LAST_ERROR_IF(written == 0 || written >= required);
    fullPath.resize(written);

    auto result = std::filesystem::path{fullPath}.lexically_normal().make_preferred().wstring();
    THROW_HR_IF(E_INVALIDARG, result.empty() || PathIsRelativeW(result.c_str()));
    return result;
}

void wsl::windows::common::installresume::ValidateIntent(const Intent& intent)
{
    ValidateString(intent.Distribution, 256);
    ValidateString(intent.Name, 256);
    ValidateString(intent.Location, 32 * 1024);

    THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), (intent.Selector == DistributionSelector::Explicit) != intent.Distribution.has_value());
    THROW_HR_IF(
        HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
        intent.Version.has_value() && *intent.Version != LXSS_WSL_VERSION_1 && *intent.Version != LXSS_WSL_VERSION_2);
    THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), intent.VhdSize.has_value() && *intent.VhdSize == 0);
    THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), intent.FixedVhd && !intent.VhdSize.has_value());
    THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), intent.FixedVhd && intent.Version == LXSS_WSL_VERSION_1);
    THROW_HR_IF(
        HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
        intent.Legacy && (intent.Name.has_value() || intent.Location.has_value() || intent.VhdSize.has_value() || intent.FixedVhd));

    if (intent.Location.has_value())
    {
        THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), CanonicalizeLocation(*intent.Location) != *intent.Location);
    }
}

void wsl::windows::common::installresume::ValidateState(const State& state)
{
    THROW_HR_IF(
        HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
        IsNullGuid(state.Generation) || IsNullGuid(state.LastAutomaticBootId) || state.WriterVersion.empty() ||
            state.WriterVersion.size() > 64 || state.WriterVersion.find(L'\0') != state.WriterVersion.npos ||
            state.AutomaticAttempts > c_maxAutomaticAttempts || (state.AttemptInProgress && state.AutomaticAttempts == 0));
    ValidateIntent(state.InstallIntent);
    ValidateString(state.DistroRegistration.DistributionName, 256);
    ValidateString(state.DistroRegistration.TargetName, 256);
    ValidateString(state.DistroRegistration.InstalledName, 256);

    switch (state.CurrentPhase)
    {
    case Phase::AwaitingPrerequisites:
        THROW_HR_IF(
            HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
            state.DistroRegistration.Status != RegistrationStatus::None ||
                state.DistroRegistration.DistributionName.has_value() || state.DistroRegistration.TargetName.has_value() ||
                state.DistroRegistration.InstalledName.has_value() || state.DistroRegistration.CommittedId.has_value());
        break;

    case Phase::InstallingDistribution:
        THROW_HR_IF(
            HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
            (state.DistroRegistration.Status != RegistrationStatus::Prepared && state.DistroRegistration.Status != RegistrationStatus::Started) ||
                !state.DistroRegistration.DistributionName.has_value() || !state.DistroRegistration.TargetName.has_value() ||
                state.DistroRegistration.InstalledName.has_value() || state.DistroRegistration.CommittedId.has_value());
        break;

    case Phase::DistributionCommitted:
        THROW_HR_IF(
            HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
            state.DistroRegistration.Status != RegistrationStatus::Committed || !state.DistroRegistration.DistributionName.has_value() ||
                !state.DistroRegistration.TargetName.has_value() || !state.DistroRegistration.InstalledName.has_value() ||
                !state.DistroRegistration.CommittedId.has_value() || IsNullGuid(*state.DistroRegistration.CommittedId));
        break;

    default:
        THROW_HR(HRESULT_FROM_WIN32(ERROR_INVALID_DATA));
    }
}

std::wstring wsl::windows::common::installresume::SerializeState(const State& state)
{
    ValidateState(state);

    const auto& intent = state.InstallIntent;
    const auto& registration = state.DistroRegistration;
    const json root{
        {"schemaVersion", c_schemaVersion},
        {"writerVersion", WideToUtf8(state.WriterVersion)},
        {"generation", WideToUtf8(GuidToString(state.Generation))},
        {"phase", ToString(state.CurrentPhase)},
        {"lastAutomaticBootId", WideToUtf8(GuidToString(state.LastAutomaticBootId))},
        {"automaticAttempts", state.AutomaticAttempts},
        {"attemptInProgress", state.AttemptInProgress},
        {"intent",
         {{"selector", ToString(intent.Selector)},
          {"distribution", WriteOptionalString(intent.Distribution)},
          {"name", WriteOptionalString(intent.Name)},
          {"location", WriteOptionalString(intent.Location)},
          {"version", intent.Version.has_value() ? json(*intent.Version) : json(nullptr)},
          {"vhdSize", WriteOptionalUnsigned(intent.VhdSize)},
          {"fixedVhd", intent.FixedVhd},
          {"legacy", intent.Legacy},
          {"webDownload", intent.WebDownload},
          {"enableWsl1", intent.EnableWsl1},
          {"noLaunch", intent.NoLaunch}}},
        {"registration",
         {{"status", ToString(registration.Status)},
          {"distributionName", WriteOptionalString(registration.DistributionName)},
          {"targetName", WriteOptionalString(registration.TargetName)},
          {"installedName", WriteOptionalString(registration.InstalledName)},
          {"committedId", WriteOptionalGuid(registration.CommittedId)}}}};

    const auto serialized = Utf8ToWide(root.dump());
    THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW), serialized.size() > c_maxStateCharacters);
    return serialized;
}

wsl::windows::common::installresume::StateValue wsl::windows::common::installresume::DecodeState(const std::optional<RawRegistryValue>& value)
{
    if (!value.has_value())
    {
        return {};
    }

    StateValue result;
    result.Kind = StateValueKind::Corrupt;
    result.Raw = value;
    try
    {
        const auto stringValue = DecodeRegistryString(*value, c_maxStateCharacters);
        if (!stringValue.has_value())
        {
            return result;
        }

        const auto root = ParseJson(*stringValue);
        if (!root.is_object() || !root.contains("schemaVersion"))
        {
            return result;
        }

        const auto schemaVersion = ReadUnsigned(root.at("schemaVersion"));
        if (schemaVersion > c_schemaVersion)
        {
            THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), schemaVersion > UINT_MAX);
            result.Kind = StateValueKind::Unsupported;
            result.UnsupportedVersion = static_cast<unsigned int>(schemaVersion);
            return result;
        }

        result.Value = ParseState(root);
        result.Kind = StateValueKind::Valid;
    }
    catch (...)
    {
    }

    return result;
}

wsl::windows::common::installresume::TriggerValue wsl::windows::common::installresume::DecodeTrigger(const std::optional<RawRegistryValue>& value)
{
    if (!value.has_value())
    {
        return {};
    }

    TriggerValue result;
    result.Kind = TriggerValueKind::Corrupt;
    result.Raw = value;
    if (const auto command = DecodeRegistryString(*value, c_maxRunCommandCharacters))
    {
        if (const auto generation = ParseRunCommand(*command))
        {
            result.Kind = TriggerValueKind::Valid;
            result.Generation = generation;
        }
    }

    return result;
}

std::wstring wsl::windows::common::installresume::GetStableLauncherPath()
{
    auto packageFamilyName = wsl::windows::common::wslutil::GetPackageFamilyName();
    packageFamilyName.resize(wcsnlen(packageFamilyName.c_str(), packageFamilyName.size()));
    if (!packageFamilyName.empty())
    {
        wil::unique_cotaskmem_string localAppData;
        THROW_IF_FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &localAppData));
        return (std::filesystem::path{localAppData.get()} / L"Microsoft" / L"WindowsApps" / packageFamilyName / WSL_BINARY_NAME)
            .lexically_normal()
            .wstring();
    }

    return wil::GetModuleFileNameW<std::wstring>(wil::GetModuleInstanceHandle());
}

std::wstring wsl::windows::common::installresume::BuildRunCommand(std::wstring_view launcher, const GUID& generation)
{
    THROW_HR_IF(
        E_INVALIDARG,
        launcher.empty() || launcher.find(L'\0') != launcher.npos || IsNullGuid(generation) ||
            PathIsRelativeW(std::wstring{launcher}.c_str()));

    auto command = wsl::shared::string::QuoteWindowsCommandLineArgument(launcher);
    command += L" " WSL_INSTALL_ARG L" " WSL_INSTALL_ARG_RESUME_LONG L" ";
    command += GuidToString(generation);
    THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW), command.size() > c_maxRunCommandCharacters);
    return command;
}

std::optional<GUID> wsl::windows::common::installresume::ParseRunCommand(std::wstring_view command)
{
    int argumentCount{};
    const std::wstring nullTerminated{command};
    const wil::unique_hlocal_ptr<LPWSTR[]> arguments{CommandLineToArgvW(nullTerminated.c_str(), &argumentCount)};
    if (!arguments || argumentCount != 4 || PathIsRelativeW(arguments[0]) || wcscmp(arguments[1], WSL_INSTALL_ARG) != 0 ||
        wcscmp(arguments[2], WSL_INSTALL_ARG_RESUME_LONG) != 0)
    {
        return {};
    }

    return GuidFromString(arguments[3]);
}

std::wstring wsl::windows::common::installresume::BuildMutexName(PSID userSid)
{
    THROW_HR_IF(E_INVALIDARG, userSid == nullptr || !IsValidSid(userSid));
    return std::format(L"Microsoft.WSL.InstallResume.{}", wsl::windows::common::wslutil::SidToString(userSid).get());
}

wsl::windows::common::installresume::MutexAcquireResult wsl::windows::common::installresume::ClassifyMutexWaitResult(DWORD waitResult)
{
    switch (waitResult)
    {
    case WAIT_OBJECT_0:
        return MutexAcquireResult::Acquired;
    case WAIT_ABANDONED:
        return MutexAcquireResult::Abandoned;
    case WAIT_TIMEOUT:
        return MutexAcquireResult::Timeout;
    case WAIT_FAILED:
        THROW_LAST_ERROR();
    default:
        THROW_HR(E_UNEXPECTED);
    }
}

wsl::windows::common::installresume::ScopedMutex::ScopedMutex(DWORD timeoutMilliseconds)
{
    const auto token = wil::open_current_access_token();
    const auto tokenUser = wil::get_token_information<TOKEN_USER>(token.get());
    const auto userSid = wsl::windows::common::wslutil::SidToString(tokenUser->User.Sid);
    const auto namespaceName = BuildMutexName(tokenUser->User.Sid);
    const auto securityDescriptorString = std::format(L"D:P(A;;GA;;;SY)(A;;GA;;;{})", userSid.get());

    wil::unique_hlocal_security_descriptor securityDescriptor;
    THROW_IF_WIN32_BOOL_FALSE(ConvertStringSecurityDescriptorToSecurityDescriptorW(
        securityDescriptorString.c_str(), SDDL_REVISION_1, &securityDescriptor, nullptr));

    SECURITY_ATTRIBUTES attributes{sizeof(attributes), securityDescriptor.get(), FALSE};
    auto boundaryDescriptor = CreateBoundaryDescriptorW(namespaceName.c_str(), 0);
    THROW_LAST_ERROR_IF(boundaryDescriptor == nullptr);
    auto deleteBoundaryDescriptor = wil::scope_exit([&]() { DeleteBoundaryDescriptor(boundaryDescriptor); });
    THROW_IF_WIN32_BOOL_FALSE(AddSIDToBoundaryDescriptor(&boundaryDescriptor, tokenUser->User.Sid));
    auto [integritySid, integritySidBuffer] =
        wsl::windows::common::security::CreateSid(SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_MEDIUM_RID);
    THROW_IF_WIN32_BOOL_FALSE(AddIntegrityLabelToBoundaryDescriptor(&boundaryDescriptor, integritySid));

    EnsureProcessPrivateNamespace(&attributes, boundaryDescriptor, namespaceName);
    m_mutex.reset(CreateMutexW(&attributes, FALSE, std::format(L"{}\\Mutex", namespaceName).c_str()));
    THROW_LAST_ERROR_IF(!m_mutex);

    m_result = ClassifyMutexWaitResult(WaitForSingleObject(m_mutex.get(), timeoutMilliseconds));
    m_owned = m_result == MutexAcquireResult::Acquired || m_result == MutexAcquireResult::Abandoned;
}

wsl::windows::common::installresume::ScopedMutex::~ScopedMutex()
{
    if (m_owned)
    {
        LOG_LAST_ERROR_IF(!ReleaseMutex(m_mutex.get()));
    }

    m_mutex.reset();
}

wsl::windows::common::installresume::MutexAcquireResult wsl::windows::common::installresume::ScopedMutex::Result() const noexcept
{
    return m_result;
}

void wsl::windows::common::installresume::ScopedMutex::Release()
{
    if (m_owned)
    {
        THROW_IF_WIN32_BOOL_FALSE(ReleaseMutex(m_mutex.get()));
        m_owned = false;
    }
}

wsl::windows::common::installresume::RegistryStore::RegistryStore()
{
    m_currentUserKey = wsl::windows::common::registry::OpenCurrentUser();
    m_lxssKey = wsl::windows::common::registry::CreateKey(m_currentUserKey.get(), LXSS_REGISTRY_PATH, KEY_READ | KEY_WRITE | DELETE);
    m_resumeKey = wsl::windows::common::registry::CreateKey(m_lxssKey.get(), c_resumeKeyName);
    m_runKey = wsl::windows::common::registry::CreateKey(m_currentUserKey.get(), c_runRegistryPath);
}

std::optional<wsl::windows::common::installresume::RawRegistryValue> wsl::windows::common::installresume::RegistryStore::ReadState() const
{
    return ReadRawRegistryValue(m_resumeKey.get(), c_stateValueName, (c_maxStateCharacters + 1) * sizeof(WCHAR));
}

std::optional<wsl::windows::common::installresume::RawRegistryValue> wsl::windows::common::installresume::RegistryStore::ReadTrigger() const
{
    return ReadRawRegistryValue(m_runKey.get(), c_triggerValueName, (c_maxRunCommandCharacters + 1) * sizeof(WCHAR));
}

void wsl::windows::common::installresume::RegistryStore::WriteState(std::wstring_view value)
{
    WriteRegistryString(m_resumeKey.get(), c_stateValueName, value, c_maxStateCharacters);
}

void wsl::windows::common::installresume::RegistryStore::WriteTrigger(std::wstring_view value)
{
    WriteRegistryString(m_runKey.get(), c_triggerValueName, value, c_maxRunCommandCharacters);
}

void wsl::windows::common::installresume::RegistryStore::DeleteState()
{
    DeleteRegistryValue(m_resumeKey.get(), c_stateValueName);
}

void wsl::windows::common::installresume::RegistryStore::DeleteTrigger()
{
    DeleteRegistryValue(m_runKey.get(), c_triggerValueName);
}

void wsl::windows::common::installresume::RegistryStore::QuarantineState(std::wstring_view reason)
{
    m_resumeKey.reset();
    const auto deleteResult = RegDeleteTreeW(m_lxssKey.get(), c_quarantineKeyName);
    THROW_WIN32_IF(deleteResult, deleteResult != ERROR_SUCCESS && deleteResult != ERROR_FILE_NOT_FOUND);
    THROW_IF_WIN32_ERROR(RegRenameKey(m_lxssKey.get(), c_resumeKeyName, c_quarantineKeyName));

    const auto quarantineKey = wsl::windows::common::registry::OpenKey(m_lxssKey.get(), c_quarantineKeyName, KEY_READ | KEY_WRITE);
    WriteRegistryString(quarantineKey.get(), c_quarantineReasonValueName, reason, 256);
    m_resumeKey = wsl::windows::common::registry::CreateKey(m_lxssKey.get(), c_resumeKeyName);
}

wsl::windows::common::installresume::RecoveryDecision wsl::windows::common::installresume::EvaluateAutomaticRecovery(
    const StateValue& state, const TriggerValue& trigger, const GUID& runnerGeneration)
{
    if (state.Kind == StateValueKind::Unsupported)
    {
        if (trigger.Kind == TriggerValueKind::Valid && AreEqual(*trigger.Generation, runnerGeneration))
        {
            return {RecoveryAction::ReportUnsupported, true};
        }

        return {};
    }

    if (state.Kind == StateValueKind::Corrupt)
    {
        if ((trigger.Kind == TriggerValueKind::Valid && AreEqual(*trigger.Generation, runnerGeneration)) ||
            trigger.Kind == TriggerValueKind::Corrupt)
        {
            return {RecoveryAction::QuarantineState, true};
        }

        return {};
    }

    if (state.Kind == StateValueKind::Missing)
    {
        if (trigger.Kind == TriggerValueKind::Valid && AreEqual(*trigger.Generation, runnerGeneration))
        {
            return {RecoveryAction::ClearOrphanTrigger, false};
        }
        if (trigger.Kind == TriggerValueKind::Corrupt)
        {
            return {RecoveryAction::DisarmTrigger, false};
        }

        return {};
    }

    WI_ASSERT(state.Value.has_value());
    if (trigger.Kind == TriggerValueKind::Missing)
    {
        return {};
    }
    if (trigger.Kind == TriggerValueKind::Corrupt)
    {
        if (AreEqual(state.Value->Generation, runnerGeneration))
        {
            return {RecoveryAction::DisarmTrigger, true};
        }

        return {};
    }

    WI_ASSERT(trigger.Generation.has_value());
    if (!AreEqual(*trigger.Generation, runnerGeneration))
    {
        return {};
    }
    if (!AreEqual(state.Value->Generation, *trigger.Generation))
    {
        return {RecoveryAction::DisarmTrigger, true};
    }

    return {RecoveryAction::Run, false};
}

wsl::windows::common::installresume::AttemptAction wsl::windows::common::installresume::EvaluateAutomaticAttempt(const State& state, const GUID& currentBootId)
{
    if (AreEqual(state.LastAutomaticBootId, currentBootId))
    {
        return AttemptAction::SameBoot;
    }
    if (state.CurrentPhase == Phase::DistributionCommitted)
    {
        return AttemptAction::CompleteCommitted;
    }
    if (state.AutomaticAttempts >= c_maxAutomaticAttempts)
    {
        return AttemptAction::Exhausted;
    }

    return AttemptAction::Start;
}

void wsl::windows::common::installresume::ReserveAutomaticAttempt(State& state, const GUID& currentBootId)
{
    THROW_HR_IF(E_UNEXPECTED, EvaluateAutomaticAttempt(state, currentBootId) != AttemptAction::Start);
    ++state.AutomaticAttempts;
    state.LastAutomaticBootId = currentBootId;
    state.AttemptInProgress = true;
}

void wsl::windows::common::installresume::CompleteAutomaticAttempt(State& state)
{
    THROW_HR_IF(E_UNEXPECTED, !state.AttemptInProgress);
    state.AttemptInProgress = false;
}

void wsl::windows::common::installresume::CancelAutomaticAttempt(State& state)
{
    THROW_HR_IF(E_UNEXPECTED, !state.AttemptInProgress || state.AutomaticAttempts == 0);
    --state.AutomaticAttempts;
    state.AttemptInProgress = false;
}

bool wsl::windows::common::installresume::IsRetryPathSafe(const std::optional<std::wstring>& location)
{
    if (!location.has_value())
    {
        return false;
    }

    const auto attributes = GetFileAttributesW(location->c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        const auto error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
        {
            return true;
        }

        THROW_WIN32(error);
    }
    if (WI_IsFlagClear(attributes, FILE_ATTRIBUTE_DIRECTORY))
    {
        return false;
    }

    std::error_code error;
    const auto begin = std::filesystem::directory_iterator{*location, error};
    if (error)
    {
        THROW_WIN32(error.value());
    }

    return begin == std::filesystem::directory_iterator{};
}
