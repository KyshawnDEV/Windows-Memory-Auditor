#include "AccessAssessment.h"
#include "WindowsHandle.h"

#include <sddl.h>
#include <algorithm>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * AccessAssessmentTests.cpp
 *
 * Verifies v0.8 exact access masks, caller metadata, fresh-handle
 * outcomes, cleanup, and conservative failure reporting.
 *
 * Owned child processes provide normal and deliberately restricted
 * process DACLs. The test never reads/writes their memory or creates
 * remote threads. Child events coordinate readiness and normal exit.
 *
 * Caller-token tests impersonate a duplicate of this test's own token,
 * then restore the thread. No privileges are enabled or elevated.
 * Synthetic fingerprints cover changes that cannot be scheduled
 * reliably inside a short live assessment.
 */

// ============================================================
// TEST HELPERS
// ============================================================

void require(bool condition, const std::string& message)
{
    // Explicit failures remain active in Release builds and are reported to CTest.
    if (!condition)
        throw std::runtime_error(message);
}

class ConsoleCapture
{
public:
    ConsoleCapture() : previous_(std::cout.rdbuf(output_.rdbuf())) {}
    ~ConsoleCapture() { std::cout.rdbuf(previous_); }
    std::string text() const { return output_.str(); }

private:
    std::ostringstream output_;
    std::streambuf* previous_;
};

const AccessProbeResult& probeWithMask(const AccessAssessment& assessment, DWORD mask)
{
    auto found = std::find_if(assessment.probes.begin(), assessment.probes.end(),
        [mask](const AccessProbeResult& probe) { return probe.definition.requestedAccess == mask; });
    require(found != assessment.probes.end(), "Expected probe mask absent");
    return *found;
}


// ============================================================
// PROFILES, ERROR MEANINGS, AND TOKEN FINGERPRINTS
// ============================================================

void testDefinitionsAndFingerprints()
{
    require(accessProbeDefinitions().size() == 8, "Access profile count changed unexpectedly");
    DWORD unrelatedRights = PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_DUP_HANDLE |
        PROCESS_SET_INFORMATION | WRITE_DAC | WRITE_OWNER;

    for (const AccessProbeDefinition& definition : accessProbeDefinitions())
    {
        /*
         * Every successful handle needs limited query access to verify
         * identity. Unrelated mutation rights and PROCESS_ALL_ACCESS
         * must not silently enter the assessment's explicit masks.
         */
        require((definition.requestedAccess & PROCESS_QUERY_LIMITED_INFORMATION) != 0 &&
                definition.requestedAccess != PROCESS_ALL_ACCESS &&
                (definition.requestedAccess & unrelatedRights) == 0,
                "Probe requested unplanned rights or omitted identity verification access");
    }

    require(accessOutcomeFromOpenError(ERROR_ACCESS_DENIED) == AccessProbeOutcome::Denied,
            "Access-denied error not identified");
    require(accessOutcomeFromOpenError(ERROR_INVALID_PARAMETER) == AccessProbeOutcome::OpenFailed &&
            accessOutcomeFromOpenError(ERROR_INVALID_HANDLE) == AccessProbeOutcome::OpenFailed,
            "Non-permission API failure mislabeled as denial");
    require(accessOutcomeFromGrantedMask(0x1028, 0x1008) == AccessProbeOutcome::RightsReduced &&
            accessOutcomeFromGrantedMask(0x1028, 0x101028) == AccessProbeOutcome::Obtained,
            "Reduced handle rights were assumed to satisfy the requested mask");

    CallerFingerprint first{};
    first.available = true;
    first.source = CallerTokenSource::Process;
    first.tokenId.LowPart = 10;
    first.modifiedId.LowPart = 20;
    CallerFingerprint second = first;
    require(sameCallerFingerprint(first, second), "Identical caller fingerprints rejected");
    second.modifiedId.LowPart++;
    require(!sameCallerFingerprint(first, second), "Modified token accepted as the same context");
    second = first;
    second.tokenId.HighPart++;
    require(!sameCallerFingerprint(first, second), "Changed token identity ignored");
    second = first;
    second.source = CallerTokenSource::Thread;
    require(!sameCallerFingerprint(first, second), "Thread/process token source change ignored");
    second = first;
    second.available = false;
    require(!sameCallerFingerprint(first, second), "Unavailable token treated as verified");
}


// ============================================================
// EFFECTIVE CALLER CONTEXT
// ============================================================

void testCallerContext()
{
    CallerFingerprint before = captureCallerFingerprint();
    CallerSecurityContext context = captureCallerSecurityContext();
    CallerFingerprint after = captureCallerFingerprint();
    require(before.available && sameCallerFingerprint(before, context.fingerprint) &&
            sameCallerFingerprint(before, after), "Caller inspection altered or failed to identify the token");
    require(context.userSid.available && context.userSid.value.find("S-1-") == 0 &&
            context.integrity.available && context.elevation.available && context.privilegesAvailable,
            "Normal caller security metadata missing");

    /*
     * Duplicate the current primary token as an impersonation token.
     * This changes the effective token source without changing users
     * or enabling privileges. The collector must prefer the thread token.
     */
    HANDLE primary = nullptr;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &primary),
            "Test token duplication access unavailable");
    WindowsHandle primaryOwner(primary);
    HANDLE duplicate = nullptr;
    require(DuplicateTokenEx(primary, TOKEN_QUERY | TOKEN_IMPERSONATE, nullptr,
            SecurityImpersonation, TokenImpersonation, &duplicate), "Test token duplication failed");
    WindowsHandle duplicateOwner(duplicate);

    {
        require(ImpersonateLoggedOnUser(duplicate), "Self-token impersonation fixture failed");

        // Restore the thread before closing its token, including when a check throws.
        struct RestoreThread
        {
            ~RestoreThread() { RevertToSelf(); }
        } restore;

        CallerSecurityContext threadContext = captureCallerSecurityContext();
        require(threadContext.fingerprint.available && threadContext.fingerprint.source == CallerTokenSource::Thread &&
                threadContext.userSid.value == context.userSid.value,
                "Effective thread token was mistaken for the primary token");
        require(!sameCallerFingerprint(before, threadContext.fingerprint),
                "Impersonation token identity was not distinguished");
    }

    require(sameCallerFingerprint(before, captureCallerFingerprint()), "Thread impersonation was not restored");
}


// ============================================================
// OWNED CHILD PROCESS FIXTURE
// ============================================================

static HANDLE createInheritableEvent()
{
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    HANDLE event = CreateEventW(&attributes, TRUE, FALSE, nullptr);
    require(event != nullptr, "Child coordination event failed");
    return event;
}

static PROCESS_INFORMATION startChild(HANDLE ready, HANDLE stop, bool restricted)
{
    std::vector<wchar_t> path(32768, L'\0');
    DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    require(length != 0 && length < path.size(), "Test executable path unavailable");
    std::wstring command = L"\"" + std::wstring(path.data(), length) + L"\" --target " +
        std::to_wstring(reinterpret_cast<std::uintptr_t>(ready)) + L" " +
        std::to_wstring(reinterpret_cast<std::uintptr_t>(stop));

    PSECURITY_DESCRIPTOR descriptor = nullptr;

    if (restricted)
    {
        /*
         * Deny fresh VM_WRITE, VM_OPERATION, and CREATE_THREAD requests.
         * Allow query, read, and synchronize so the assessment can verify
         * identity and report independent successful and denied profiles.
         * Apply this DACL only to the child created by this test.
         */
        std::wstring dacl = L"D:P(D;;0x2A;;;WD)(A;;0x101410;;;WD)";
        CallerSecurityContext caller = captureCallerSecurityContext();

        /*
         * AppContainer callers also need the intended access granted to
         * their package context. An Everyone ACE alone is insufficient.
         * Grant only the same query/read/synchronize mask to this package;
         * keep the Everyone write/operation/thread deny ACE unchanged.
         */
        if (caller.appContainer.available && caller.appContainer.value == "Yes")
        {
            require(caller.appContainerSid.available && caller.appContainerSid.value.find("S-1-") == 0,
                    "AppContainer package SID unavailable for the restricted fixture");
            std::wstring packageSid(caller.appContainerSid.value.begin(), caller.appContainerSid.value.end());
            dacl += L"(A;;0x101410;;;" + packageSid + L")";
        }

        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            dacl.c_str(), SDDL_REVISION_1, &descriptor, nullptr),
            "Restricted child DACL fixture failed");
    }

    std::unique_ptr<void, decltype(&LocalFree)> descriptorOwner(descriptor, &LocalFree);
    SECURITY_ATTRIBUTES processAttributes{};
    processAttributes.nLength = sizeof(processAttributes);
    processAttributes.lpSecurityDescriptor = descriptor;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    BOOL created = CreateProcessW(path.data(), command.data(), restricted ? &processAttributes : nullptr,
        nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
    DWORD errorCode = created ? ERROR_SUCCESS : GetLastError();
    require(created != FALSE, "Owned child creation failed: " + std::to_string(errorCode));
    return process;
}

/*
 * ChildFixture
 *
 * Owns two inherited events and the process/thread handles returned
 * by CreateProcess. Member owners release handles if setup throws.
 * The child signals readiness, then waits for the stop event.
 *
 * The creator already holds a process handle independently of the DACL.
 * This is why fresh-request denials must not claim that existing handles
 * or every possible access path have been ruled out.
 */
class ChildFixture
{
public:
    explicit ChildFixture(bool restricted)
        : information_(startChild(ready_, stop_, restricted)),
          processOwner_(information_.hProcess), threadOwner_(information_.hThread)
    {
        if (WaitForSingleObject(ready_, 5000) != WAIT_OBJECT_0)
        {
            stop();
            throw std::runtime_error("Owned child readiness failed");
        }
    }

    ~ChildFixture() { stop(); }
    ChildFixture(const ChildFixture&) = delete;
    ChildFixture& operator=(const ChildFixture&) = delete;
    DWORD pid() const { return information_.dwProcessId; }
    HANDLE process() const { return information_.hProcess; }

    void stop()
    {
        if (stopped_)
            return;

        SetEvent(stop_);

        if (WaitForSingleObject(information_.hProcess, 5000) != WAIT_OBJECT_0)
        {
            // Emergency test cleanup applies only to the process created by this fixture.
            TerminateProcess(information_.hProcess, 1);
            WaitForSingleObject(information_.hProcess, 5000);
        }

        stopped_ = true;
    }

private:
    HANDLE ready_ = createInheritableEvent();
    WindowsHandle readyOwner_{ready_};
    HANDLE stop_ = createInheritableEvent();
    WindowsHandle stopOwner_{stop_};
    PROCESS_INFORMATION information_{};
    WindowsHandle processOwner_;
    WindowsHandle threadOwner_;
    bool stopped_ = false;
};

static int runTarget(const char* readyArgument, const char* stopArgument)
{
    HANDLE ready = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::stoull(readyArgument)));
    HANDLE stop = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::stoull(stopArgument)));
    WindowsHandle readyOwner(ready);
    WindowsHandle stopOwner(stop);
    require(SetEvent(ready) && WaitForSingleObject(stop, INFINITE) == WAIT_OBJECT_0,
            "Child coordination failed");

    // Deliberately use exit code 259 to verify that synchronization, not STILL_ACTIVE, detects exit.
    return 259;
}


// ============================================================
// LIVE PERMITTED, DENIED, AND EXITED TARGETS
// ============================================================

void testLiveProbes()
{
    ChildFixture target(false);
    CallerFingerprint before = captureCallerFingerprint();
    AccessAssessment assessment = assessProcessAccess(target.pid());
    require(assessment.status == AccessAssessmentStatus::Complete && assessment.identityVerified,
            "Normal live access assessment did not complete");
    require(std::all_of(assessment.probes.begin(), assessment.probes.end(), [](const AccessProbeResult& probe)
        {
            bool verified = probe.grantedMaskAvailable && probe.outcome == AccessProbeOutcome::Obtained &&
                (probe.grantedAccess & probe.definition.requestedAccess) == probe.definition.requestedAccess;
            bool unknown = !probe.grantedMaskAvailable && probe.outcome == AccessProbeOutcome::GrantedMaskUnavailable;
            return probe.attempted && probe.handleObtained && (verified || unknown) && probe.cleanupErrorCode == ERROR_SUCCESS;
        }), "Normal owned child access request failed or had its granted mask misreported");
    require(sameCallerFingerprint(before, captureCallerFingerprint()), "Assessment altered caller privileges or token");

    /*
     * Warm-up above allows any Windows lookup caches to initialize.
     * A second assessment must return the process handle count to its
     * original value, showing that probe, anchor, and token handles close.
     */
    DWORD handlesBefore = 0, handlesAfter = 0;
    require(GetProcessHandleCount(GetCurrentProcess(), &handlesBefore), "Initial handle count failed");
    assessProcessAccess(target.pid());
    require(GetProcessHandleCount(GetCurrentProcess(), &handlesAfter) && handlesBefore == handlesAfter,
            "Access assessment leaked handles");

    ChildFixture restricted(true);
    assessment = assessProcessAccess(restricted.pid());

    if (assessment.status != AccessAssessmentStatus::Complete)
        displayAccessAssessment(assessment);

    require(assessment.status == AccessAssessmentStatus::Complete, "Restricted child assessment failed verification");
    require(probeWithMask(assessment, PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION).outcome == AccessProbeOutcome::Obtained,
            "Restricted DACL unexpectedly denied its allowed read profile");

    /*
     * An already enabled SeDebugPrivilege can bypass the test's DACL.
     * Do not disable it or make a false denial assertion in that context.
     * The error-classification tests still cover denial reporting there.
     */
    if (assessment.caller.debugPrivilege != DebugPrivilegeState::Enabled)
    {
        require(probeWithMask(assessment, PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION).outcome == AccessProbeOutcome::Denied &&
                probeWithMask(assessment, PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION).outcome == AccessProbeOutcome::Denied &&
                probeWithMask(assessment, PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION).outcome == AccessProbeOutcome::Denied,
                "Restricted DACL did not deny the planned write/thread profiles");
    }
    else
    {
        std::cout << "[INFO] DACL-denial expectation omitted: caller already has enabled SeDebugPrivilege.\n";
    }

    target.stop();
    DWORD exitCode = 0;
    require(GetExitCodeProcess(target.process(), &exitCode) && exitCode == 259,
            "Exited-target fixture did not return its deliberate exit code");
    assessment = assessProcessAccess(target.pid());
    require((assessment.status == AccessAssessmentStatus::TargetExited ||
             assessment.status == AccessAssessmentStatus::Unavailable) &&
            std::none_of(assessment.probes.begin(), assessment.probes.end(),
                [](const AccessProbeResult& probe) { return probe.handleObtained; }),
            "Exited process was reported as a live permitted target");

    assessment = assessProcessAccess(0);
    require(assessment.status == AccessAssessmentStatus::Unavailable &&
            assessment.targetErrorCode == ERROR_INVALID_PARAMETER &&
            std::none_of(assessment.probes.begin(), assessment.probes.end(),
                [](const AccessProbeResult& probe) { return probe.attempted; }),
            "Invalid target PID was reported as denied or probed");
}


// ============================================================
// CONSERVATIVE REPORTING
// ============================================================

void testReporting()
{
    AccessAssessment assessment{};
    assessment.pid = 123;
    assessment.status = AccessAssessmentStatus::Complete;
    assessment.identityVerified = true;
    AccessProbeResult probe{};
    probe.definition = {"Write-related", PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION};
    probe.attempted = true;
    probe.outcome = AccessProbeOutcome::Denied;
    probe.openErrorCode = ERROR_ACCESS_DENIED;
    assessment.probes.push_back(probe);

    {
        ConsoleCapture capture;
        displayAccessAssessment(assessment);
        std::string text = capture.text();
        require(text.find("Requested mask: 0x1020") != std::string::npos &&
                text.find("REQUEST DENIED") != std::string::npos && text.find("Open error: 5") != std::string::npos,
                "Exact mask or access-denied evidence missing");
        require(text.find("other callers and existing handles were not") != std::string::npos &&
                text.find("does not prove region writability or successful code injection") != std::string::npos &&
                text.find("did not enable privileges, elevate, or change exposure priorities") != std::string::npos,
                "Assessment scope limitations missing");
    }

    assessment.status = AccessAssessmentStatus::CallerChanged;
    assessment.probes[0].outcome = AccessProbeOutcome::CallerChanged;
    {
        ConsoleCapture capture;
        displayAccessAssessment(assessment);
        require(capture.text().find("CALLER TOKEN CHANGED") != std::string::npos,
                "Changed caller context was hidden");
    }

    // A successful open without mask inspection is evidence of a handle, not verified requested rights.
    assessment.status = AccessAssessmentStatus::Complete;
    assessment.probes[0].handleObtained = true;
    assessment.probes[0].openErrorCode = ERROR_SUCCESS;
    assessment.probes[0].outcome = AccessProbeOutcome::GrantedMaskUnavailable;
    {
        ConsoleCapture capture;
        displayAccessAssessment(assessment);
        require(capture.text().find("HANDLE RETURNED; GRANTED MASK UNAVAILABLE") != std::string::npos &&
                capture.text().find("REQUESTED HANDLE RIGHTS VERIFIED") == std::string::npos,
                "Unknown granted mask was reported as verified rights");
    }
}


// ============================================================
// TEST PROGRAM ENTRY POINT
// ============================================================

int main(int argc, char* argv[])
{
    try
    {
        // Child mode performs only event coordination, not the parent's test suite.
        if (argc == 4 && std::string(argv[1]) == "--target")
            return runTarget(argv[2], argv[3]);

        testDefinitionsAndFingerprints();
        testCallerContext();
        testLiveProbes();
        testReporting();
        std::cout << "All current-caller access assessment checks passed.\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "[FAIL] " << error.what() << '\n';
        return 1;
    }
}
