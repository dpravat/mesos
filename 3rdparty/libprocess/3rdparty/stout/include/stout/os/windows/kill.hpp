// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __STOUT_OS_WINDOWS_KILL_HPP__
#define __STOUT_OS_WINDOWS_KILL_HPP__

#include <stout/windows.hpp>
#include <logging/logging.hpp>
#include <stout/windows/os.hpp>
#include <TlHelp32.h>

#define KILL_PASS 0
#define KILL_FAIL -1

namespace os {

  inline int SuspendResumeProcess(pid_t pid, int sig)
  {
    // To suspend a process, we have to suspend all threads
    // in this process.

    // Make sure sig values could only be SIGSTOP or SIGCONT.
    if (sig != SIGSTOP && sig != SIGCONT) {
      LOG(FATAL)
        << "Failed call to os::SuspendResumeProcess() "
        << "Sginal value: '" << sig << "' cannot be handled. "
        << "Signal value to SuspendResumeProcess can only be "
        << "'SIGSTOP' or 'SIGCONT'";
      return KILL_FAIL;
    }

    bool exists = false;
    Result<bool> findprocess_result = os::FindProcess(pid, exists);
    if (findprocess_result.isError()) {
      LOG(FATAL) << findprocess_result.error();
      return KILL_FAIL;
    }

    if (!exists) {
      LOG(ERROR)
        << "os::SuspendResumeProcess cannot find process "
        << "with pid: '" << pid << "'";
      return KILL_FAIL;
    }

    // Get a snapshot of the threads in the system.
    HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
    if (snapshot_handle == INVALID_HANDLE_VALUE ||
      snapshot_handle == NULL) {
      LOG(FATAL)
        << (WindowsError("os::SuspendResumeProcess(): \
          Failed call to CreateToolhelp32Snapshot.",
          GetLastError())).message;
      return KILL_FAIL;
    }

    std::shared_ptr<void> safe_snapshot_handle(snapshot_handle, ::CloseHandle);

    THREADENTRY32 thread_entry;
    thread_entry.dwSize = sizeof(THREADENTRY32);

    // Point to the first thread and start loop.
    DWORD last_error = ERROR_SUCCESS;
    bool bcontinue = Thread32First(safe_snapshot_handle.get(), &thread_entry);
    if (!bcontinue) {
      // No threads returned. Most likely an error but
      // will handle all paths.
      last_error = GetLastError();
      if (last_error != ERROR_NO_MORE_FILES &&
        last_error != ERROR_SUCCESS) {
        LOG(FATAL)
          << (WindowsError("os::SuspendResumeProcess(): \
            Failed call to Thread32First.",
            last_error)).message;
        return KILL_FAIL;
      }

      LOG(WARNING)
        << (WindowsError("os::SuspendResumeProcess(): \
          Thread32First did not return first thread.",
          last_error)).message;
      return KILL_PASS;
    }

    while (bcontinue) {
      HANDLE thread_handle = NULL;

      // If current thread is part of the process;
      // apply action based on passed in signal.
      if (thread_entry.th32OwnerProcessID == pid) {
        thread_handle = OpenThread(
          THREAD_ALL_ACCESS,
          false,
          thread_entry.th32ThreadID);

        // We will go with the assumption: if thread handle is not available
        // then we can just continue.
        if (thread_handle == INVALID_HANDLE_VALUE ||
          thread_handle == NULL) {
          LOG(WARNING)
            << (WindowsError("os::SuspendResumeProcess(): \
              Thread handle is invalid within process.")).message;
          continue;
        }

        // Suspend the thread.
        if (sig == SIGSTOP) {
          if (-1 == SuspendThread(thread_handle)) {
            LOG(ERROR)
              << (WindowsError("os::SuspendResumeProcess(): \
                Failed call to SuspendThread.",
                GetLastError())).message;
          }
        }

        // Resume the thread.
        else if (sig == SIGCONT) {
          if (-1 == ResumeThread(thread_handle)) {
            LOG(ERROR)
              << (WindowsError("os::SuspendResumeProcess(): \
                Failed call to ResumeThread.",
                GetLastError())).message;
          }
        }

        // Clean up for this iteration.
        CloseHandle(thread_handle);
        thread_handle = NULL;
      }

      bcontinue = Thread32Next(safe_snapshot_handle.get(), &thread_entry);
      if (!bcontinue) {
        last_error = GetLastError();
        if (last_error != ERROR_NO_MORE_FILES &&
          last_error != ERROR_SUCCESS) {
          LOG(FATAL)
            << (WindowsError("os::SuspendResumeProcess(): \
              Failed to call Thread32Next.",
              last_error)).message;
          return KILL_FAIL;
        }
      }
    };

    return KILL_PASS;
  }


  inline int KillProcess(pid_t pid)
  {
    bool exists = false;
    Result<bool> findprocess_result = os::FindProcess(pid, exists);
    if (findprocess_result.isError()) {
      LOG(FATAL) << findprocess_result.error();
      return KILL_FAIL;
    }

    if (!exists) {
      LOG(ERROR)
        << "os::KillProcess cannot find process "
        << "with pid: '" << pid << "'";
      return KILL_PASS;
    }

    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (process_handle == INVALID_HANDLE_VALUE ||
      process_handle == NULL) {
      LOG(FATAL)
        << (WindowsError("os::TerminateProcess(): \
          Failed call to OpenProcess.",
          GetLastError())).message;
      return KILL_FAIL;
    }

    std::shared_ptr<void> safe_process_handle(process_handle, ::CloseHandle);

    BOOL result = ::TerminateProcess(safe_process_handle.get(), 1);
    if (!result) {
      LOG(FATAL)
        << (WindowsError("os::KillProcess(): \
          Failed call to TerminateProcess.",
          GetLastError())).message;
      return KILL_FAIL;
    }

    return KILL_PASS;
  }


  inline int kill(pid_t pid, int sig)
  {
    // If sig is SIGSTOP or SIGCONT
    // call SuspendResumeProcess.
    // If sig is SIGKILL call TerminateProcess
    // otherwise return -1 (fail).
    if (sig == SIGSTOP || sig == SIGCONT) {
      return SuspendResumeProcess(pid, sig);
    }
    else if (sig == SIGKILL) {
      return KillProcess(pid);
    }

    LOG(FATAL)
      << "Failed call to os::kill() "
      << "Sginal value: '" << sig << "' cannot be handled. "
      << "Valid Signal values to Windows os::kill() are "
      << "'SIGSTOP', 'SIGCONT' and 'SIGKILL'";
    return KILL_FAIL;
  }

} // namespace os {

#endif // __STOUT_OS_WINDOWS_KILL_HPP__