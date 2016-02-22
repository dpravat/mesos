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

#include <queue>

#include <TlHelp32.h>
#include <errno.h>

#define KILL_PASS 0
#define KILL_FAIL -1

namespace os {

  inline DWORD ResumeThread(HANDLE thread_handle) {
    DWORD suspend_count = -1;
    while ((suspend_count = ::ResumeThread(thread_handle)) != 0 &&
            suspend_count != -1);
    return suspend_count;
  }

  inline DWORD SuspendThread(HANDLE thread_handle) {
    DWORD suspend_count = -1;
    while ((suspend_count = ::SuspendThread(thread_handle)) != 0 &&
            suspend_count != -1);
    return suspend_count;
  }

  inline void CloseHandles(std::queue<HANDLE>& thread_handles)
  {
    while (!thread_handles.empty()) {
      HANDLE thread_handle = thread_handles.front();
      thread_handles.pop();

      if (thread_handle != NULL &&
        thread_handle != INVALID_HANDLE_VALUE) {
        ::CloseHandle(thread_handle);
      }

      return;
    }
  }

  inline void ResumeSuspendedThreads(std::queue<HANDLE>& thread_handles)
  {
    while (!thread_handles.empty()) {
      HANDLE thread_handle = thread_handles.front();
      thread_handles.pop();

      if (thread_handle != NULL &&
        thread_handle != INVALID_HANDLE_VALUE) {
        os::ResumeThread(thread_handle);
      }

      return;
    }
  }

  inline void SuspendResumedThreads(std::queue<HANDLE>& thread_handles)
  {
    while (!thread_handles.empty()) {
      HANDLE thread_handle = thread_handles.front();
      thread_handles.pop();

      if (thread_handle != NULL &&
        thread_handle != INVALID_HANDLE_VALUE) {
        os::SuspendThread(thread_handle);
      }

      return;
    }
  }

  inline void RevertThreads(std::queue<HANDLE>& thread_handles, int sig)
  {
    if (sig == SIGSTOP) {
      os::ResumeSuspendedThreads(thread_handles);
    }
    else if (sig == SIGCONT) {
      os::SuspendResumedThreads(thread_handles);
    }
  }

  inline int SuspendResumeProcess(pid_t pid, int sig)
  {
    // To suspend a process, we have to suspend all threads
    // in this process.

    // Make sure sig values can only be SIGSTOP or SIGCONT.
    if (sig != SIGSTOP && sig != SIGCONT) {
      LOG(FATAL)
        << "Failed call to os::SuspendResumeProcess() "
        << "Sginal value: '" << sig << "' cannot be handled. "
        << "Signal value to SuspendResumeProcess can only be "
        << "'SIGSTOP' or 'SIGCONT'";
      // set errno to EINVAL (An invalid signal was specified).
      errno = EINVAL;
      return KILL_FAIL;
    }

    Result<bool> findprocess_result = os::FindProcess(pid);
    if (findprocess_result.isError()) {
      LOG(FATAL) << findprocess_result.error();
      // Since this is failure in finding the process,
      // set errno to ESRCH.
      errno = ESRCH;
      return KILL_FAIL;
    }

    if (!findprocess_result.get()) {
      LOG(ERROR)
        << "os::SuspendResumeProcess cannot find process "
        << "with pid: '" << pid << "'";
      // set errno to ESRCH (The pid or process group does not exist).
      errno = ESRCH;
      return KILL_FAIL;
    }

    // Get a snapshot of the threads in the system.
    HANDLE snapshot_handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
    if (snapshot_handle == INVALID_HANDLE_VALUE) {
      LOG(FATAL)
        << (WindowsError("os::SuspendResumeProcess(): \
          Failed call to CreateToolhelp32Snapshot.")).message;
      // Since this is failure in finding threads of a process,
      // set errno to ESRCH.
      errno = ESRCH;
      return KILL_FAIL;
    }

    std::shared_ptr<void> safe_snapshot_handle(snapshot_handle, ::CloseHandle);

    THREADENTRY32 thread_entry;
    thread_entry.dwSize = sizeof(THREADENTRY32);

    // Point to the first thread and start loop.
    bool bcontinue = ::Thread32First(safe_snapshot_handle.get(), &thread_entry);
    if (!bcontinue) {
      // No threads returned. Most likely an error but
      // will handle all paths.
      if (::GetLastError() != ERROR_NO_MORE_FILES) {
        LOG(FATAL)
          << (WindowsError("os::SuspendResumeProcess(): \
            Failed call to Thread32First.")).message;
        // Since this is failure in finding threads of a process,
        // set errno to ESRCH.
        errno = ESRCH;
        return KILL_FAIL;
      }

      LOG(WARNING)
        << (WindowsError("os::SuspendResumeProcess(): \
          Thread32First did not return first thread.")).message;
      return KILL_PASS;
    }

    std::queue<HANDLE> changed_threads;
    std::queue<HANDLE> opened_threads;

    while (bcontinue) {
      HANDLE thread_handle = NULL;

      // If current thread is part of the process;
      // apply action based on passed in signal.
      if (thread_entry.th32OwnerProcessID == pid) {
        thread_handle = ::OpenThread(
          THREAD_ALL_ACCESS,
          false,
          thread_entry.th32ThreadID);

        // We will go with the assumption: if thread handle is not available
        // then we can just continue.
        if (thread_handle == NULL) {
          LOG(WARNING)
            << (WindowsError("os::SuspendResumeProcess(): \
              Thread handle is invalid within process.")).message;
          continue;
        }
        // Keep track of opened threads for clean up.
        opened_threads.push(thread_handle);

        // Suspend the thread.
        if (sig == SIGSTOP) {
          if (-1 == os::SuspendThread(thread_handle)) {
            LOG(ERROR)
              << (WindowsError("os::SuspendResumeProcess(): \
                Failed call to SuspendThread.")).message;
            // Revert, cleanup and exit.
            os::RevertThreads(changed_threads, sig);
            os::CloseHandles(opened_threads);
            errno = ESRCH;
            return KILL_FAIL;
          }
          // Everythread that was suspended is added to the
          // queue for revert purposes in case of error.
          changed_threads.push(thread_handle);
        }
        // Resume the thread.
        else if (sig == SIGCONT) {
          if (-1 == os::ResumeThread(thread_handle)) {
            LOG(ERROR)
              << (WindowsError("os::SuspendResumeProcess(): \
                Failed call to ResumeThread.")).message;
            // Revert, cleanup and exit.
            os::RevertThreads(changed_threads, sig);
            os::CloseHandles(opened_threads);
            errno = ESRCH;
            return KILL_FAIL;
            break;
          }
          // Everythread that was resumed is added to the
          // queue for revert purposes in case of error.
          changed_threads.push(thread_handle);
        }
      }

      bcontinue = ::Thread32Next(safe_snapshot_handle.get(), &thread_entry);
      if (!bcontinue) {
        if (::GetLastError() != ERROR_NO_MORE_FILES) {
          LOG(FATAL)
            << (WindowsError("os::SuspendResumeProcess(): \
              Failed to call Thread32Next.")).message;
          // Since this is failure in finding threads of a process,
          // set errno to ESRCH.
          // Revert, cleanup and exit.
          os::RevertThreads(changed_threads, sig);
          os::CloseHandles(opened_threads);
          errno = ESRCH;
          return KILL_FAIL;
        }
      }
    };

    os::CloseHandles(opened_threads);
    return KILL_PASS;
  }


  inline int KillProcess(pid_t pid)
  {
    Result<bool> findprocess_result = os::FindProcess(pid);
    if (findprocess_result.isError()) {
      LOG(FATAL) << findprocess_result.error();
      // Since this is failure in finding the process,
      // set errno to ESRCH.
      errno = ESRCH;
      return KILL_FAIL;
    }

    if (!findprocess_result.get()) {
      LOG(ERROR)
        << "os::KillProcess cannot find process "
        << "with pid: '" << pid << "'";
      // set errno to ESRCH (The pid or process group does not exist).
      errno = ESRCH;
      return KILL_FAIL;
    }

    HANDLE process_handle = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (process_handle == NULL) {
      LOG(FATAL)
        << (WindowsError("os::TerminateProcess(): \
          Failed call to OpenProcess.")).message;
      if (::GetLastError() == ERROR_ACCESS_DENIED) {
        // Set errno to EPERM (permission error).
        errno = EPERM;
      }
      else {
        errno = ESRCH;
      }
      return KILL_FAIL;
    }

    std::shared_ptr<void> safe_process_handle(process_handle, ::CloseHandle);

    BOOL result = ::TerminateProcess(safe_process_handle.get(), 1);
    if (!result) {
      LOG(FATAL)
        << (WindowsError("os::KillProcess(): \
          Failed call to TerminateProcess.")).message;
      if (::GetLastError() == ERROR_ACCESS_DENIED) {
        // Set errno to EPERM (permission error).
        errno = EPERM;
      }
      else {
        errno = ESRCH;
      }
      return KILL_FAIL;
    }

    return KILL_PASS;
  }


  inline int kill(pid_t pid, int sig)
  {
    // If this is windows system process
    // with pid 0x00000000 then return
    // an error
    if (pid == 0x00000000) {
      LOG(FATAL)
        << "Failed call to os::kill() "
        << "Windows Process Id 0x00000000 is the System "
        << "Process and is not handled by os::kill().";
      errno = EINVAL;
      return KILL_FAIL;
    }

    // If sig is SIGSTOP or SIGCONT
    // call SuspendResumeProcess.
    // If sig is SIGKILL call TerminateProcess
    // otherwise return -1 (fail).
    if (sig == SIGSTOP || sig == SIGCONT) {
      return os::SuspendResumeProcess(pid, sig);
    }
    else if (sig == SIGKILL) {
      return os::KillProcess(pid);
    }

    LOG(FATAL)
      << "Failed call to os::kill() "
      << "Sginal value: '" << sig << "' is not handled. "
      << "Valid Signal values for Windows os::kill() are "
      << "'SIGSTOP', 'SIGCONT' and 'SIGKILL'";
    errno = EINVAL;
    return KILL_FAIL;
  }

} // namespace os {

#endif // __STOUT_OS_WINDOWS_KILL_HPP__
