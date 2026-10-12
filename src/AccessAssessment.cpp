#include "AccessAssessment.h"
#include "ScanComparison.h"
#include "WindowsHandle.h"

#include <sddl.h>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>

/*
 * AccessAssessment.cpp
 *
 * Observes which fresh process-handle requests succeed under the
 * current effective caller token. No capabilities are exercised.
 *
 * Token APIs are used only with TOKEN_QUERY. This implementation
 * does not adjust privileges, elevate, impersonate, read/write
 * target memory, change protections, or create target threads.
 */

// ============================================================
// EFFECTIVE CALLER TOKEN
// ============================================================

/*
 * openEffectiveToken()
 *
 * A thread impersonation token takes precedence over the process
 * token. Fall back only for ERROR_NO_TOKEN, not for access errors.
 * OpenAsSelf permits inspecting a thread token using the process
 * context; it does not change the effective context for OpenProcess.
 */
static HANDLE openEffectiveToken(CallerTokenSource& source, DWORD& errorCode)
{
    HANDLE token = nullptr;
    source = CallerTokenSource::Unknown;
    errorCode = ERROR_SUCCESS;

    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token))
    {
        source = CallerTokenSource::Thread;
        return token;
    }

    errorCode = GetLastError();

    if (errorCode != ERROR_NO_TOKEN)
        return nullptr;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        errorCode = GetLastError();
        return nullptr;
    }

    source = CallerTokenSource::Process;
    errorCode = ERROR_SUCCESS;
    return token;
}

/*
 * tokenBytes()
 *
 * Variable-size token information requires a size query followed
 * by a buffer query. Retry a bounded number of times if the token
 * changes between calls. A failure remains unavailable metadata.
 */
static bool tokenBytes(HANDLE token, TOKEN_INFORMATION_CLASS information,
    std::vector<BYTE>& buffer, DWORD& errorCode)
{
    for (unsigned int attempt = 0; attempt < 3; attempt++)
    {
        DWORD required = 0;
        GetTokenInformation(token, information, nullptr, 0, &required);
        errorCode = GetLastError();

        if (required == 0 || errorCode != ERROR_INSUFFICIENT_BUFFER)
            return false;

        buffer.resize(required);

        if (GetTokenInformation(token, information, buffer.data(), required, &required))
        {
            buffer.resize(required);
            errorCode = ERROR_SUCCESS;
            return true;
        }

        errorCode = GetLastError();

        if (errorCode != ERROR_INSUFFICIENT_BUFFER)
            return false;
    }

    return false;
}

static bool fixedTokenInformation(HANDLE token, TOKEN_INFORMATION_CLASS information,
    void* value, DWORD size, DWORD& errorCode)
{
    DWORD returned = 0;

    if (!GetTokenInformation(token, information, value, size, &returned))
    {
        errorCode = GetLastError();
        return false;
    }

    errorCode = returned < size ? ERROR_INVALID_DATA : ERROR_SUCCESS;
    return errorCode == ERROR_SUCCESS;
}

static CallerFingerprint fingerprintForToken(HANDLE token, CallerTokenSource source)
{
    CallerFingerprint fingerprint{};
    fingerprint.source = source;
    TOKEN_STATISTICS statistics{};

    if (fixedTokenInformation(token, TokenStatistics, &statistics, sizeof(statistics), fingerprint.errorCode))
    {
        fingerprint.tokenId = statistics.TokenId;
        fingerprint.modifiedId = statistics.ModifiedId;
        fingerprint.available = true;
    }

    return fingerprint;
}

CallerFingerprint captureCallerFingerprint()
{
    CallerTokenSource source;
    DWORD errorCode = ERROR_SUCCESS;
    HANDLE token = openEffectiveToken(source, errorCode);

    if (token == nullptr)
    {
        CallerFingerprint fingerprint{};
        fingerprint.errorCode = errorCode;
        return fingerprint;
    }

    WindowsHandle owner(token);
    return fingerprintForToken(token, source);
}

bool sameCallerFingerprint(const CallerFingerprint& left, const CallerFingerprint& right)
{
    return left.available && right.available && left.source != CallerTokenSource::Unknown && left.source == right.source &&
        left.tokenId.LowPart == right.tokenId.LowPart && left.tokenId.HighPart == right.tokenId.HighPart &&
        left.modifiedId.LowPart == right.modifiedId.LowPart && left.modifiedId.HighPart == right.modifiedId.HighPart;
}


// ============================================================
// CALLER SECURITY METADATA
// ============================================================

static std::string privilegeName(const LUID& luid)
{
    DWORD length = 0;
    LUID value = luid;
    LookupPrivilegeNameA(nullptr, &value, nullptr, &length);

    if (length != 0)
    {
        std::vector<char> name(length + 1, '\0');
        DWORD capacity = static_cast<DWORD>(name.size());

        if (LookupPrivilegeNameA(nullptr, &value, name.data(), &capacity))
            return std::string(name.data());
    }

    // A name lookup failure must not hide an enabled privilege.
    std::ostringstream output;
    output << "Unnamed privilege (LUID 0x" << std::hex << std::uppercase
           << static_cast<DWORD>(luid.HighPart) << ':' << luid.LowPart << ')';
    return output.str();
}

CallerSecurityContext captureCallerSecurityContext()
{
    CallerSecurityContext context{};
    CallerTokenSource source;
    DWORD errorCode = ERROR_SUCCESS;
    HANDLE token = openEffectiveToken(source, errorCode);

    if (token == nullptr)
    {
        context.fingerprint.errorCode = errorCode;
        return context;
    }

    WindowsHandle owner(token);
    context.fingerprint = fingerprintForToken(token, source);
    std::vector<BYTE> buffer;

    // A SID is an unambiguous caller identifier and avoids account-name lookup or network access.
    if (tokenBytes(token, TokenUser, buffer, context.userSid.errorCode) && buffer.size() >= sizeof(TOKEN_USER))
    {
        const TOKEN_USER* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
        LPSTR sidText = nullptr;

        if (ConvertSidToStringSidA(user->User.Sid, &sidText))
        {
            // SID strings use LocalAlloc ownership, not CloseHandle ownership.
            std::unique_ptr<char, decltype(&LocalFree)> sidOwner(sidText, &LocalFree);
            context.userSid.value = sidText;
            context.userSid.available = true;
        }
        else
        {
            context.userSid.errorCode = GetLastError();
        }
    }

    if (tokenBytes(token, TokenIntegrityLevel, buffer, context.integrity.errorCode) &&
        buffer.size() >= sizeof(TOKEN_MANDATORY_LABEL))
    {
        PSID sid = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(buffer.data())->Label.Sid;

        if (IsValidSid(sid) && *GetSidSubAuthorityCount(sid) != 0)
        {
            DWORD rid = *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1);
            const char* name = "Other";

            switch (rid)
            {
                case 0x0000: name = "Untrusted"; break;
                case 0x1000: name = "Low"; break;
                case 0x2000: name = "Medium"; break;
                case 0x2100: name = "Medium Plus"; break;
                case 0x3000: name = "High"; break;
                case 0x4000: name = "System"; break;
                case 0x5000: name = "Protected-process integrity RID"; break;
            }

            std::ostringstream text;
            text << name << " (RID 0x" << std::hex << std::uppercase << rid << ')';
            context.integrity.value = text.str();
            context.integrity.available = true;
        }
        else
        {
            context.integrity.errorCode = ERROR_INVALID_SID;
        }
    }

    TOKEN_ELEVATION elevation{};

    if (fixedTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), context.elevation.errorCode))
    {
        context.elevation.available = true;
        context.elevation.value = elevation.TokenIsElevated != 0 ? "Yes" : "No";
    }

    // Restricted SIDs and AppContainer state are reported independently of elevation.
    if (tokenBytes(token, TokenRestrictedSids, buffer, context.restricted.errorCode) &&
        buffer.size() >= offsetof(TOKEN_GROUPS, Groups))
    {
        context.restricted.available = true;
        context.restricted.value = reinterpret_cast<const TOKEN_GROUPS*>(buffer.data())->GroupCount != 0 ? "Yes" : "No";
    }

    DWORD appContainer = 0;

    if (fixedTokenInformation(token, TokenIsAppContainer, &appContainer, sizeof(appContainer), context.appContainer.errorCode))
    {
        context.appContainer.available = true;
        context.appContainer.value = appContainer != 0 ? "Yes" : "No";
    }

    /*
     * AppContainer access checks include the package/capability context,
     * not just the user SID. Record the package SID when present so
     * grants observed in a sandbox are not described as general user access.
     */
    if (tokenBytes(token, TokenAppContainerSid, buffer, context.appContainerSid.errorCode) &&
        buffer.size() >= sizeof(TOKEN_APPCONTAINER_INFORMATION))
    {
        PSID sid = reinterpret_cast<const TOKEN_APPCONTAINER_INFORMATION*>(buffer.data())->TokenAppContainer;

        if (sid == nullptr && context.appContainer.available && appContainer == 0)
        {
            context.appContainerSid.available = true;
            context.appContainerSid.value = "Not applicable";
        }
        else
        {
            LPSTR sidText = nullptr;

            if (sid != nullptr && ConvertSidToStringSidA(sid, &sidText))
            {
                std::unique_ptr<char, decltype(&LocalFree)> sidOwner(sidText, &LocalFree);
                context.appContainerSid.value = sidText;
                context.appContainerSid.available = true;
            }
            else
            {
                context.appContainerSid.errorCode = sid == nullptr ? ERROR_INVALID_SID : GetLastError();
            }
        }
    }

    if (tokenBytes(token, TokenPrivileges, buffer, context.privilegesErrorCode) &&
        buffer.size() >= offsetof(TOKEN_PRIVILEGES, Privileges))
    {
        const TOKEN_PRIVILEGES* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(buffer.data());
        std::size_t capacity = (buffer.size() - offsetof(TOKEN_PRIVILEGES, Privileges)) / sizeof(LUID_AND_ATTRIBUTES);

        if (privileges->PrivilegeCount <= capacity)
        {
            context.privilegesAvailable = true;
            LUID debugLuid{};
            bool debugKnown = LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &debugLuid) != FALSE;
            context.debugPrivilege = debugKnown ? DebugPrivilegeState::Absent : DebugPrivilegeState::Unknown;

            for (DWORD index = 0; index < privileges->PrivilegeCount; index++)
            {
                const LUID_AND_ATTRIBUTES& privilege = privileges->Privileges[index];
                bool enabled = (privilege.Attributes & SE_PRIVILEGE_ENABLED) != 0;

                if (enabled)
                    context.enabledPrivileges.push_back(privilegeName(privilege.Luid));

                if (debugKnown && privilege.Luid.LowPart == debugLuid.LowPart && privilege.Luid.HighPart == debugLuid.HighPart)
                    context.debugPrivilege = enabled ? DebugPrivilegeState::Enabled : DebugPrivilegeState::Disabled;
            }
        }
        else
        {
            context.privilegesErrorCode = ERROR_INVALID_DATA;
        }
    }

    // Reject a caller label assembled while its token security attributes changed.
    CallerFingerprint after = fingerprintForToken(token, source);

    if (!sameCallerFingerprint(context.fingerprint, after))
    {
        context.fingerprint.available = false;
        context.fingerprint.errorCode = after.available ? ERROR_RETRY : after.errorCode;
    }

    return context;
}


// ============================================================
// EXPLICIT ACCESS PROFILES
// ============================================================

const std::vector<AccessProbeDefinition>& accessProbeDefinitions()
{
    /*
     * Limited query access is added to every request so the returned
     * handle can verify PID and creation time. A denial therefore
     * applies to the exact combined mask, not to one isolated right.
     */
    static const std::vector<AccessProbeDefinition> definitions =
    {
        {"Limited query", PROCESS_QUERY_LIMITED_INFORMATION},
        {"Memory query", PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION},
        {"Read-related", PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION},
        {"Write-related", PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION},
        {"Memory operations", PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION},
        {"Write + operations", PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION},
        {"Thread creation", PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION},
        {"Write + operations + thread", PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
            PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION}
    };
    return definitions;
}

AccessProbeOutcome accessOutcomeFromOpenError(DWORD errorCode)
{
    // Invalid PIDs and other API failures are not evidence of an access denial.
    return errorCode == ERROR_ACCESS_DENIED ? AccessProbeOutcome::Denied : AccessProbeOutcome::OpenFailed;
}

static bool processIdentity(HANDLE process, DWORD& pid, std::uint64_t& creationTime, DWORD& errorCode)
{
    pid = GetProcessId(process);

    if (pid == 0)
    {
        errorCode = GetLastError();
        return false;
    }

    FILETIME creation{}, exit{}, kernel{}, user{};

    if (!GetProcessTimes(process, &creation, &exit, &kernel, &user))
    {
        errorCode = GetLastError();
        return false;
    }

    creationTime = (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
    errorCode = creationTime == 0 ? ERROR_INVALID_DATA : ERROR_SUCCESS;
    return errorCode == ERROR_SUCCESS;
}

static bool verifyCaller(AccessAssessment& assessment)
{
    CallerFingerprint current = captureCallerFingerprint();

    if (!current.available)
    {
        assessment.status = AccessAssessmentStatus::CallerUnverified;
        assessment.callerVerificationErrorCode = current.errorCode;
        return false;
    }

    if (!sameCallerFingerprint(assessment.caller.fingerprint, current))
    {
        assessment.status = AccessAssessmentStatus::CallerChanged;
        return false;
    }

    return true;
}


// ============================================================
// ACCESS PROBES AND TARGET LIFETIME
// ============================================================

static void runAccessProbes(AccessAssessment& assessment)
{
    if (!assessment.caller.fingerprint.available)
    {
        assessment.status = AccessAssessmentStatus::CallerUnverified;
        assessment.callerVerificationErrorCode = assessment.caller.fingerprint.errorCode;
        return;
    }

    if (assessment.pid == 0)
    {
        assessment.targetErrorCode = ERROR_INVALID_PARAMETER;
        return;
    }

    if (!verifyCaller(assessment))
        return;

    /*
     * The anchor requires only limited query and synchronization.
     * Keep it alive across all fresh opens. WaitForSingleObject(0)
     * detects process exit without confusing exit code 259 with
     * STILL_ACTIVE. No wait blocks the interactive audit.
     */
    HANDLE anchor = OpenProcess(assessment.anchorRequestedAccess, FALSE, assessment.pid);

    if (anchor == nullptr)
    {
        assessment.targetErrorCode = GetLastError();
        return;
    }

    WindowsHandle anchorOwner(anchor);
    DWORD observedPid = 0;

    if (!processIdentity(anchor, observedPid, assessment.processCreationTime, assessment.targetErrorCode))
        return;

    if (observedPid != assessment.pid)
    {
        assessment.status = AccessAssessmentStatus::IdentityMismatch;
        return;
    }

    assessment.identityVerified = true;

    for (AccessProbeResult& probe : assessment.probes)
    {
        DWORD waitStatus = WaitForSingleObject(anchor, 0);

        if (waitStatus == WAIT_OBJECT_0)
        {
            assessment.status = AccessAssessmentStatus::TargetExited;
            return;
        }

        if (waitStatus != WAIT_TIMEOUT)
        {
            assessment.targetErrorCode = GetLastError();
            return;
        }

        if (!verifyCaller(assessment))
            return;

        probe.attempted = true;
        HANDLE process = OpenProcess(probe.definition.requestedAccess, FALSE, assessment.pid);

        if (process == nullptr)
        {
            probe.openErrorCode = GetLastError();
            probe.outcome = accessOutcomeFromOpenError(probe.openErrorCode);
        }
        else
        {
            WindowsHandle owner(process);
            probe.handleObtained = true;
            std::uint64_t observedCreation = 0;

            if (!processIdentity(process, observedPid, observedCreation, probe.verificationErrorCode))
            {
                probe.outcome = AccessProbeOutcome::VerificationFailed;
            }
            else if (observedPid != assessment.pid || observedCreation != assessment.processCreationTime)
            {
                probe.outcome = AccessProbeOutcome::IdentityMismatch;
            }
            else
            {
                probe.outcome = AccessProbeOutcome::Obtained;
            }

            // Close without using any read, write, operation, or thread capability.
            if (!owner.close())
                probe.cleanupErrorCode = GetLastError();
        }

        if (!verifyCaller(assessment))
        {
            probe.outcome = assessment.status == AccessAssessmentStatus::CallerChanged
                ? AccessProbeOutcome::CallerChanged : AccessProbeOutcome::VerificationFailed;
            probe.verificationErrorCode = assessment.callerVerificationErrorCode;
            return;
        }

        waitStatus = WaitForSingleObject(anchor, 0);

        if (waitStatus == WAIT_OBJECT_0)
        {
            probe.outcome = AccessProbeOutcome::TargetExited;
            assessment.status = AccessAssessmentStatus::TargetExited;
            return;
        }

        if (waitStatus != WAIT_TIMEOUT)
        {
            assessment.targetErrorCode = GetLastError();
            probe.outcome = AccessProbeOutcome::VerificationFailed;
            probe.verificationErrorCode = assessment.targetErrorCode;
            return;
        }

        if (probe.outcome == AccessProbeOutcome::IdentityMismatch)
        {
            assessment.status = AccessAssessmentStatus::IdentityMismatch;
            return;
        }

        if (probe.outcome == AccessProbeOutcome::VerificationFailed)
        {
            assessment.targetErrorCode = probe.verificationErrorCode;
            return;
        }
    }

    // Complete means all profiles were attempted, not that their requests succeeded.
    assessment.status = AccessAssessmentStatus::Complete;
}

AccessAssessment assessProcessAccess(DWORD pid)
{
    AccessAssessment assessment{};
    assessment.pid = pid;
    GetSystemTimeAsFileTime(&assessment.startedAt);
    assessment.caller = captureCallerSecurityContext();

    for (const AccessProbeDefinition& definition : accessProbeDefinitions())
    {
        AccessProbeResult probe{};
        probe.definition = definition;
        assessment.probes.push_back(probe);
    }

    runAccessProbes(assessment);
    GetSystemTimeAsFileTime(&assessment.completedAt);
    return assessment;
}


// ============================================================
// ACCESS ASSESSMENT REPORT
// ============================================================

static void displaySecurityField(const char* label, const SecurityContextField& field)
{
    std::cout << label << ": ";

    if (field.available)
        std::cout << field.value;
    else
    {
        std::cout << "Unavailable";

        if (field.errorCode != ERROR_SUCCESS)
            std::cout << " (Windows error: " << field.errorCode << ')';
    }

    std::cout << '\n';
}

void displayAccessAssessment(const AccessAssessment& assessment)
{
    std::cout << "\n================ CURRENT-CALLER ACCESS ASSESSMENT ================\n";
    std::cout << "Target PID: " << assessment.pid << '\n';
    std::cout << "Started: " << scanTimeToString(assessment.startedAt) << '\n';
    std::cout << "Finished: " << scanTimeToString(assessment.completedAt) << '\n';
    std::cout << "Assessment status: ";

    switch (assessment.status)
    {
        case AccessAssessmentStatus::Complete: std::cout << "COMPLETE (all profiles attempted)"; break;
        case AccessAssessmentStatus::Unavailable: std::cout << "UNAVAILABLE"; break;
        case AccessAssessmentStatus::TargetExited: std::cout << "TARGET EXITED"; break;
        case AccessAssessmentStatus::IdentityMismatch: std::cout << "TARGET IDENTITY MISMATCH"; break;
        case AccessAssessmentStatus::CallerChanged: std::cout << "CALLER TOKEN CHANGED"; break;
        case AccessAssessmentStatus::CallerUnverified: std::cout << "CALLER TOKEN UNVERIFIED"; break;
    }

    std::cout << '\n';

    if (assessment.targetErrorCode != ERROR_SUCCESS)
        std::cout << "Target verification error: " << assessment.targetErrorCode << '\n';

    if (assessment.callerVerificationErrorCode != ERROR_SUCCESS)
        std::cout << "Caller verification error: " << assessment.callerVerificationErrorCode << '\n';

    std::cout << "Target identity: " << (assessment.identityVerified ? "PID + creation time verified" : "Unavailable") << '\n';
    std::cout << "Anchor request (limited query + synchronize): 0x"
              << std::hex << std::uppercase << assessment.anchorRequestedAccess << std::dec << '\n';
    std::cout << "\n---------------- OBSERVED CALLER CONTEXT ----------------\n";
    std::cout << "Effective token: ";

    switch (assessment.caller.fingerprint.source)
    {
        case CallerTokenSource::Process: std::cout << "Process token"; break;
        case CallerTokenSource::Thread: std::cout << "Thread impersonation token"; break;
        case CallerTokenSource::Unknown: std::cout << "Unavailable"; break;
    }

    std::cout << '\n';
    displaySecurityField("User SID", assessment.caller.userSid);
    displaySecurityField("Integrity level", assessment.caller.integrity);
    displaySecurityField("Elevated", assessment.caller.elevation);
    displaySecurityField("Restricted SIDs present", assessment.caller.restricted);
    displaySecurityField("AppContainer", assessment.caller.appContainer);
    displaySecurityField("AppContainer package SID", assessment.caller.appContainerSid);
    std::cout << "SeDebugPrivilege: ";

    switch (assessment.caller.debugPrivilege)
    {
        case DebugPrivilegeState::Enabled: std::cout << "Enabled in the observed token"; break;
        case DebugPrivilegeState::Disabled: std::cout << "Present but disabled"; break;
        case DebugPrivilegeState::Absent: std::cout << "Absent"; break;
        case DebugPrivilegeState::Unknown: std::cout << "Unavailable"; break;
    }

    std::cout << "\nEnabled privileges:\n";

    if (!assessment.caller.privilegesAvailable)
    {
        std::cout << "  Unavailable";

        if (assessment.caller.privilegesErrorCode != ERROR_SUCCESS)
            std::cout << " (Windows error: " << assessment.caller.privilegesErrorCode << ')';

        std::cout << '\n';
    }
    else if (assessment.caller.enabledPrivileges.empty())
        std::cout << "  None observed\n";
    else
    {
        for (const std::string& privilege : assessment.caller.enabledPrivileges)
            std::cout << "  " << privilege << '\n';
    }

    std::cout << "\n---------------- FRESH HANDLE REQUESTS ----------------\n";

    for (const AccessProbeResult& probe : assessment.probes)
    {
        std::cout << probe.definition.name << " | Requested mask: 0x" << std::hex
                  << std::uppercase << probe.definition.requestedAccess << std::dec << " | ";

        switch (probe.outcome)
        {
            case AccessProbeOutcome::NotAttempted: std::cout << "NOT ATTEMPTED"; break;
            case AccessProbeOutcome::Obtained: std::cout << "HANDLE ACCESS OBTAINED"; break;
            case AccessProbeOutcome::Denied: std::cout << "REQUEST DENIED"; break;
            case AccessProbeOutcome::OpenFailed: std::cout << "OPEN FAILED"; break;
            case AccessProbeOutcome::VerificationFailed: std::cout << "VERIFICATION FAILED"; break;
            case AccessProbeOutcome::IdentityMismatch: std::cout << "TARGET IDENTITY MISMATCH"; break;
            case AccessProbeOutcome::TargetExited: std::cout << "TARGET EXITED DURING PROBE"; break;
            case AccessProbeOutcome::CallerChanged: std::cout << "CALLER TOKEN CHANGED DURING PROBE"; break;
        }

        if (probe.attempted)
            std::cout << " | OpenProcess returned a handle: " << (probe.handleObtained ? "Yes" : "No");

        if (probe.openErrorCode != ERROR_SUCCESS)
            std::cout << " | Open error: " << probe.openErrorCode;

        if (probe.verificationErrorCode != ERROR_SUCCESS)
            std::cout << " | Verification error: " << probe.verificationErrorCode;

        if (probe.cleanupErrorCode != ERROR_SUCCESS)
            std::cout << " | Cleanup error: " << probe.cleanupErrorCode;

        std::cout << '\n';
    }

    std::cout << "\n[INFO] Every profile includes limited query access for identity verification.\n";
    std::cout << "[INFO] Denials apply to the exact requested mask; their cause is not diagnosed.\n";
    std::cout << "[INFO] Only this caller's fresh handle requests were assessed; other callers and existing handles were not.\n";
    std::cout << "[INFO] Probe capabilities were not exercised; no target memory or threads were changed.\n";
    std::cout << "[INFO] Handle access does not prove region writability or successful code injection.\n";
    std::cout << "[INFO] The auditor did not enable privileges, elevate, or change exposure priorities.\n";
    std::cout << "[INFO] Results are sampled observations; caller and target checks are not an atomic snapshot.\n";
}
