#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

/*
 * AccessAssessment.h
 *
 * Stores v0.8 fresh-handle access observations for the current caller.
 * These results are separate from memory exposure classifications.
 * Obtaining rights does not prove a region is writable or executable,
 * and does not establish that code injection would succeed.
 */
enum class CallerTokenSource
{
    Unknown,
    Process,
    Thread
};

enum class DebugPrivilegeState
{
    Unknown,
    Absent,
    Disabled,
    Enabled
};

struct SecurityContextField
{
    bool available = false;
    std::string value;
    DWORD errorCode = ERROR_SUCCESS;
};

/*
 * CallerFingerprint
 *
 * TokenId identifies the effective token. ModifiedId changes when
 * its security attributes change. Source distinguishes process
 * and thread impersonation tokens. These observations are not
 * an atomic lock on the caller's security context.
 */
struct CallerFingerprint
{
    bool available = false;
    CallerTokenSource source = CallerTokenSource::Unknown;
    LUID tokenId{};
    LUID modifiedId{};
    DWORD errorCode = ERROR_SUCCESS;
};

struct CallerSecurityContext
{
    CallerFingerprint fingerprint;
    SecurityContextField userSid;
    SecurityContextField integrity;
    SecurityContextField elevation;
    SecurityContextField restricted;
    SecurityContextField appContainer;
    SecurityContextField appContainerSid;
    bool privilegesAvailable = false;
    std::vector<std::string> enabledPrivileges;
    DWORD privilegesErrorCode = ERROR_SUCCESS;
    DebugPrivilegeState debugPrivilege = DebugPrivilegeState::Unknown;
};

struct AccessProbeDefinition
{
    std::string name;

    // Includes PROCESS_QUERY_LIMITED_INFORMATION for per-handle identity checks.
    DWORD requestedAccess = 0;
};

enum class AccessProbeOutcome
{
    NotAttempted,
    Obtained,
    Denied,
    OpenFailed,
    VerificationFailed,
    IdentityMismatch,
    TargetExited,
    CallerChanged
};

struct AccessProbeResult
{
    AccessProbeDefinition definition;
    AccessProbeOutcome outcome = AccessProbeOutcome::NotAttempted;
    bool attempted = false;
    bool handleObtained = false;
    DWORD openErrorCode = ERROR_SUCCESS;
    DWORD verificationErrorCode = ERROR_SUCCESS;
    DWORD cleanupErrorCode = ERROR_SUCCESS;
};

enum class AccessAssessmentStatus
{
    Complete,
    Unavailable,
    TargetExited,
    IdentityMismatch,
    CallerChanged,
    CallerUnverified
};

struct AccessAssessment
{
    DWORD pid = 0;
    std::uint64_t processCreationTime = 0;
    bool identityVerified = false;

    // The retained anchor verifies identity and accurately detects process exit.
    DWORD anchorRequestedAccess = PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;
    DWORD targetErrorCode = ERROR_SUCCESS;
    DWORD callerVerificationErrorCode = ERROR_SUCCESS;
    AccessAssessmentStatus status = AccessAssessmentStatus::Unavailable;
    FILETIME startedAt{};
    FILETIME completedAt{};
    CallerSecurityContext caller;
    std::vector<AccessProbeResult> probes;
};

// Observe the effective token; do not enable privileges or impersonate a different caller.
CallerSecurityContext captureCallerSecurityContext();
CallerFingerprint captureCallerFingerprint();
bool sameCallerFingerprint(const CallerFingerprint& left, const CallerFingerprint& right);

// Fixed, explicit masks avoid PROCESS_ALL_ACCESS and keep each request independently reportable.
const std::vector<AccessProbeDefinition>& accessProbeDefinitions();
AccessProbeOutcome accessOutcomeFromOpenError(DWORD errorCode);

// Obtain and immediately close probe handles without exercising their capabilities.
AccessAssessment assessProcessAccess(DWORD pid);
void displayAccessAssessment(const AccessAssessment& assessment);
