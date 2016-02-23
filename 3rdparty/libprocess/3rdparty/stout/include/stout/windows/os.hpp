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

#ifndef __STOUT_WINDOWS_OS_HPP__
#define __STOUT_WINDOWS_OS_HPP__

#include <direct.h>
#include <io.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include <sys/utime.h>

#include <list>
#include <map>
#include <set>
#include <string>

#include <stout/duration.hpp>
#include <stout/none.hpp>
#include <stout/nothing.hpp>
#include <stout/option.hpp>
#include <stout/path.hpp>
#include <stout/try.hpp>
#include <stout/windows.hpp>

#include <stout/os/os.hpp>
#include <stout/os/read.hpp>

#include <stout/os/raw/environment.hpp>


namespace os {

inline Try<std::list<Process>> processes()
{
  return std::list<Process>();
}


inline Option<Process> process(
    pid_t pid,
    const std::list<Process>& processes)
{
  foreach(const Process& process, processes) {
    if (process.pid == pid) {
      return process;
    }
  }
  return None();
}

inline std::set<pid_t> children(
    pid_t pid,
    const std::list<Process>& processes,
    bool recursive = true)
{
  // Perform a breadth first search for descendants.
  std::set<pid_t> descendants;
  std::queue<pid_t> parents;
  parents.push(pid);
  do {
    pid_t parent = parents.front();
    parents.pop();

    // Search for children of parent.
    foreach(const Process& process, processes) {
      if (process.parent == parent) {
      // Have we seen this child yet?
        if (descendants.insert(process.pid).second) {
          parents.push(process.pid);
        }
      }
    }
  } while (recursive && !parents.empty());

  return descendants;
}

inline Try<std::set<pid_t> > children(pid_t pid, bool recursive = true)
{
  const Try<std::list<Process>> processes = os::processes();

  if (processes.isError()) {
    return Error(processes.error());
  }

  return children(pid, processes.get(), recursive);
}

inline int pagesize()
{
  SYSTEM_INFO si = {0};
  GetSystemInfo(&si);
  return si.dwPageSize;
};

// Sets the value associated with the specified key in the set of
// environment variables.
inline void setenv(const std::string& key,
                   const std::string& value,
                   bool overwrite = true)
{
  // Do not set the variable if already set and `overwrite` was not specified.
  if (!overwrite) {
    const DWORD bytes = ::GetEnvironmentVariable(key.c_str(), NULL, 0);
    const DWORD result = ::GetLastError();

    // Per MSDN[1], `GetEnvironmentVariable` returns 0 on error and sets the
    // error code to `ERROR_ENVVAR_NOT_FOUND` if the variable was not found.
    //
    // [1] https://msdn.microsoft.com/en-us/library/windows/desktop/ms683188(v=vs.85).aspx
    if (bytes != 0 || result != ERROR_ENVVAR_NOT_FOUND) {
      return;
    }
  }

  // `SetEnvironmentVariable` returns an error code, but we can't act on it.
  ::SetEnvironmentVariable(key.c_str(), value.c_str());
}


// Unsets the value associated with the specified key in the set of
// environment variables.
inline void unsetenv(const std::string& key)
{
  ::SetEnvironmentVariable(key.c_str(), NULL);
}


// Suspends execution of the calling process until a child specified
// by pid argument has changed state. By default, waitpid() waits only
// for termninated children, but this behavior is modifiable via the
// options argument
//
// The value of pid can be:
// <-1: meaning wait for any child process whose process group ID is equal
// to the absolute value of pid.
// -1: meaning wait for any child process.
// 0: meaning wait for any child process whose process group ID is equal to
// that of the calling process.
// >0: meaning wait for the child whose process ID is equal to the value of
// pid.
// The value of options is an OR of zero or more of the following constants:
// WNOHANG: return immediately if no child has exited.
// WUNTRACED: also return if a child has stopped (but not traced via
//  ptrace(2)). Status for traced children
//  which have stopped is provided even if this option is not specified.
//
// If status is not NULL, waitpid() stores status information in the int to
// which it points.
//
// Returns a value equal to the process ID of the child process for which
// status is reported.  If the status is not available, 0 is returned.
// Otherwise, -1 shall be returend and errno set to indicate the error.

inline pid_t waitpid(pid_t pid, int *status, int options)
{
  // For now, we only implement: (pid > 0) && (options is 0 or WNOHANG)
  if ((pid <= 0) || (options != 0 && options != WNOHANG))
  {
    // Function not implemented
    errno = ENOSYS;
    return -1;
  }

  // TODO(yisun) : check pid is one of the child processes
  // if not, set errno to ECHILD and return -1

  // Open the child process
  HANDLE hProcess;
  hProcess = ::OpenProcess(
    PROCESS_QUERY_INFORMATION | SYNCHRONIZE,
    FALSE,
    static_cast<DWORD>(pid));

  // Error out if not able to open
  if (hProcess == NULL)
  {
    // Failed to open the child process
    errno = ECHILD;
    return -1;
  }

  std::shared_ptr<void> hSafeProcess(hProcess, ::CloseHandle);

  // Wait for child to terminate by default
  // otherwise (WNOHANG), no wait
  DWORD dwMilliseconds = (options == 0) ? INFINITE : 0;

  // Wait for the child process
  DWORD dwRes = ::WaitForSingleObject(hSafeProcess.get(), dwMilliseconds);

  // Error out if wait failed
  if ((options == 0 && dwRes != WAIT_OBJECT_0) ||
    (options == WNOHANG && dwRes != WAIT_OBJECT_0 && dwRes != WAIT_TIMEOUT))
  {
    // Failed to wait the child process
    errno = ECHILD;
    return -1;
  }

  // Child not terminated yet in the case of WNOHANG
  if (dwRes == WAIT_TIMEOUT)
  {
    return 0;
  }

  // dwRes == WAIT_OBJECT_0: retrieve the process termination status
  DWORD dwExitCode = 0;
  if (!::GetExitCodeProcess(hSafeProcess.get(), &dwExitCode))
  {
    // Failed to retrieve the status
    errno = ECHILD;
    return -1;
  }

  // Return the exit code in status
  if (status != NULL)
  {
    *status = dwExitCode;
  }

  // Return the pid of the child process for which the status is reported
  return pid;
}

  // This function is used to map the error code from gethostname() to a
  // message string. The specific error code is retrieved by calling
  //  WSAGetLastError(). FormatMessage() is used to obtain the message string.
  //
  // In this Windows version, argument err is not used; it's here for
  // compatibility.

inline const char *hstrerror(int err)
{
  static char buffer[256];

  ::FormatMessage(
    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL,
    WSAGetLastError(),
    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
    buffer,
    sizeof(buffer) / sizeof(char),
    NULL);

  return buffer;
}


// This function is a portable version of execvpe ('p' means searching
// executable from PATH and 'e' means setting environments). We add
// this function because it is not available on all systems.
//
// NOTE: This function is not thread safe. It is supposed to be used
// only after fork (when there is only one thread). This function is
// async signal safe.
inline int execvpe(const char* file, char** argv, char** envp) = delete;


inline Try<Nothing> chown(
    uid_t uid,
    gid_t gid,
    const std::string& path,
    bool recursive) = delete;


inline Try<Nothing> chmod(const std::string& path, int mode) = delete;


inline Try<Nothing> mknod(
    const std::string& path,
    mode_t mode,
    dev_t dev) = delete;


// Suspends execution for the given duration.
inline Try<Nothing> sleep(const Duration& duration)
{
  DWORD milliseconds = static_cast<DWORD>(duration.ms());
  ::Sleep(milliseconds);

  return Nothing();
}


// Returns the list of files that match the given (shell) pattern.
// NOTE: Deleted on Windows, as a POSIX-API-compliant `glob` is much more
// trouble than its worth, considering our relatively simple usage.
inline Try<std::list<std::string>> glob(const std::string& pattern) = delete;


// Returns the total number of cpus (cores).
inline Try<long> cpus()
{
  SYSTEM_INFO sysInfo;
  ::GetSystemInfo(&sysInfo);
  return static_cast<long>(sysInfo.dwNumberOfProcessors);
}

// Returns load struct with average system loads for the last
// 1, 5 and 15 minutes respectively.
// Load values should be interpreted as usual average loads from
// uptime(1).
inline Try<Load> loadavg()
{
  // no Windows equivalent, return an error until there is a need
  return ErrnoError("Failed to determine system load averages");
}


// Returns the total size of main and free memory.
inline Try<Memory> memory()
{
  Memory memory;

  MEMORYSTATUSEX memory_status;
  memory_status.dwLength = sizeof(MEMORYSTATUSEX);
  if (!::GlobalMemoryStatusEx(&memory_status)) {
    return WindowsError("memory(): Could not call GlobalMemoryStatusEx");
  }

  memory.total = Bytes(memory_status.ullTotalPhys);
  memory.free = Bytes(memory_status.ullAvailPhys);
  memory.totalSwap = Bytes(memory_status.ullTotalPageFile);
  memory.freeSwap = Bytes(memory_status.ullAvailPageFile);

  return memory;
}


// Overload of os::pids for filtering by groups and sessions.
// A group / session id of 0 will fitler on the group / session ID
// of the calling process.
inline Try<std::set<pid_t>> pids(Option<pid_t> group, Option<pid_t> session)
{
  // Windows does not have the concept of a process group, so we need to
  // enumerate all processes.
  //
  // The list of processes might differ between calls, so continue calling
  // `EnumProcesses` until the output buffer is large enough. The call is
  // considered to fully succeed when the function returns non-zero and the
  // number of bytes returned is less than the size of the `pids` array. If
  // that's not the case, then we need to increase the size of the `pids` array
  // and attempt the call again.
  //
  // To minimize the number of calls (at the expense
  // or memory), we choose to allocate double the amount suggested by
  // `EnumProcesses`.
  DWORD *pids = NULL;
  DWORD bytes = 1024;
  DWORD pidsSize = 0;

  // TODO(alexnaparu): Set a limit to the memory that can be used.
  while (pidsSize <= bytes) {
    pidsSize = 2 * bytes;
    pids = (DWORD *)realloc(pids, pidsSize);
    if (!::EnumProcesses(pids, pidsSize, &bytes)) {
      free(pids);
      return WindowsError("`os::pids()`: Failed to call `EnumProcesses`");
  }
}

std::set<pid_t> result;
for (DWORD i = 0; i < bytes / sizeof(DWORD); i++) {
  result.insert(pids[i]);
}

free(pids);
return result;
}


// Return the system information.
inline Try<UTSInfo> uname()
{
  UTSInfo info;

  OSVERSIONINFOEX os_version;
  os_version.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
  if (!::GetVersionEx((LPOSVERSIONINFO)&os_version)) {
    return WindowsError("os::uname(): Failed to call GetVersionEx");
  }

  switch (os_version.wProductType) {
  case VER_NT_DOMAIN_CONTROLLER:
  case VER_NT_SERVER:
    info.sysname = "Windows Server";
    break;
  default:
    info.sysname = "Windows";
  }

  info.release = std::to_string(os_version.dwMajorVersion) + "." +
    std::to_string(os_version.dwMinorVersion);
  info.version = std::to_string(os_version.dwBuildNumber);
  if (os_version.szCSDVersion[0] != '\0') {
    info.version.append(" ");
    info.version.append(os_version.szCSDVersion);
  }

  // Get DNS name of the local computer. First, find the size of the output
  // buffer.
  DWORD size = 0;
  if (!::GetComputerNameEx(ComputerNameDnsHostname, NULL, &size) &&
    ::GetLastError() != ERROR_MORE_DATA) {
    return WindowsError("os::uname(): Failed to call GetComputerNameEx");
  }

  std::shared_ptr<char> computer_name(
    (char *)malloc((size + 1) * sizeof(char)));

  if (!::GetComputerNameEx(ComputerNameDnsHostname, computer_name.get(),
    &size)) {
    return WindowsError("os::uname(): Failed to call GetComputerNameEx");
  }

  info.nodename = computer_name.get();

  // Get OS architecture
  SYSTEM_INFO system_info;
  ::GetNativeSystemInfo(&system_info);
  switch (system_info.wProcessorArchitecture) {
  case PROCESSOR_ARCHITECTURE_AMD64:
    info.machine = "AMD64";
    break;
  case PROCESSOR_ARCHITECTURE_ARM:
    info.machine = "ARM";
    break;
  case PROCESSOR_ARCHITECTURE_IA64:
    info.machine = "IA64";
    break;
  case PROCESSOR_ARCHITECTURE_INTEL:
    info.machine = "x86";
    break;
  default:
    info.machine = "Unknown";
  }

  return info;
}


inline size_t recv(int sockfd, void *buf, size_t len, int flags) {
  return ::recv(sockfd, (char*)buf, len, flags);
}

inline int setsockopt(int socket, int level, int option_name,
                      const void *option_value, socklen_t option_len) {
  return ::setsockopt(socket, level, option_name, (const char*)option_value,
                      option_len);
}

inline int getsockopt(int socket, int level, int option_name,
                      void* option_value, socklen_t* option_len) {
  return ::getsockopt(socket, level, option_name, (char*)option_value,
                      option_len);
}

// Looks in the environment variables for the specified key and
// returns a string representation of its value. If no environment
// variable matching key is found, None() is returned.
inline Option<std::string> getenv(const std::string& key)
{
  char* value = ::getenv(key.c_str());

  if (value == NULL) {
    return None();
  }

  return std::string(value);
}

inline struct tm* gmtime_r(const time_t* timep, struct tm* result)
{
  // gmtime_s returns 0 if successful.
  if (gmtime_s(result, timep) == 0)
  {
    return result;
  }

  return NULL;
}


inline Try<bool> access(const std::string& fileName, int how)
{
  if (::_access(fileName.c_str(), how) != 0) {
    return ErrnoError("access: Could not access path '" + fileName + "'");
  }

  return true;
}

inline Result<bool> FindProcess(
  pid_t pid,
  bool& exists,
  PPROCESSENTRY32 process_entry_ptr)
{
  // Initialize output paramter 'exists'.
  exists = false;

  if (NULL == process_entry_ptr) {
    return WindowsError(
        "os::FindProcess(): 'process_entry_pointer' input parameter cannot be "
        "null");
  }

  // Get a snapshot of the proceses in the system.
  HANDLE snapshot_handle = CreateToolhelp32Snapshot(
    TH32CS_SNAPPROCESS,
    pid);
  if (snapshot_handle == INVALID_HANDLE_VALUE ||
    snapshot_handle == NULL) {
    return WindowsError(
        "os::FindProcess(): Failed to call CreateToolhelp32Snapshot");
  }

  std::shared_ptr<void> safe_snapshot_handle
    (snapshot_handle,
      ::CloseHandle);

  // Initialize process entry.
  ZeroMemory(process_entry_ptr, sizeof(PROCESSENTRY32));
  process_entry_ptr->dwSize = sizeof(PROCESSENTRY32);

  // Point to the first process and start loop to
  // find process.
  DWORD last_error = ERROR_SUCCESS;
  bool bcontinue = Process32First(
    safe_snapshot_handle.get(),
    process_entry_ptr);
  if (!bcontinue) {
    // No processes returned. Most likely an error but
    // will handle all paths.
    last_error = GetLastError();
    if (last_error != ERROR_NO_MORE_FILES &&
      last_error != ERROR_SUCCESS) {
      return WindowsError("os::FindProcess(): Failed to call Process32Next");
    }

    return true;
  }

  while (bcontinue) {
    if (process_entry_ptr->th32ProcessID == pid) {
      exists = true;
      break;
    }

    bcontinue = Process32Next(safe_snapshot_handle.get(), process_entry_ptr);
    if (!bcontinue) {
      last_error = GetLastError();
      if (last_error != ERROR_NO_MORE_FILES &&
        last_error != ERROR_SUCCESS) {
        return WindowsError("os::FindProcess(): Failed to call Process32Next");
      }
    }
  }

  return true;
}

inline Result<bool> FindProcess(
  pid_t pid,
  bool& exists)
{
  PROCESSENTRY32 process_entry;
  return FindProcess(pid, exists, &process_entry);
}

inline Result<Process> process(pid_t pid)
{
  pid_t process_id = 0;
  pid_t parent_process_id = 0;
  pid_t session_id = 0;
  std::string executable_filename = "";
  size_t wss = 0;
  double user_time = 0;
  double system_time = 0;

  // Find process with pid.
  PROCESSENTRY32 process_entry;
  bool process_exists = false;
  Result<bool> findprocess_result = FindProcess(
    pid,
    process_exists,
    &process_entry);

  if (findprocess_result.isError()) {
    return WindowsError(findprocess_result.error());
  }

  // If process does not exist simply return
  // none. No need to return error here.
  // See linux.hpp implementation logic.
  if (!process_exists) {
    return None();
  }

  // Process exists. Open process and get stats.
  // Get process id and parent process id and filename.
  process_id = process_entry.th32ProcessID;
  parent_process_id = process_entry.th32ParentProcessID;
  executable_filename = process_entry.szExeFile;

  HANDLE process_handle = OpenProcess(
    THREAD_ALL_ACCESS,
    false,
    process_id);
  if (process_handle == INVALID_HANDLE_VALUE ||
    process_handle == NULL) {
    return WindowsError("os::process(): Failed to call OpenProcess");
  }

  std::shared_ptr<void> safe_process_handle(process_handle, ::CloseHandle);

  // Get Windows Working set size (Resident set size in linux).
  PROCESS_MEMORY_COUNTERS proc_mem_counters;
  bool result = GetProcessMemoryInfo(
    safe_process_handle.get(),
    &proc_mem_counters,
    sizeof(proc_mem_counters));
  if (!result) {
    return WindowsError("os::process(): Failed to call GetProcessMemoryInfo");
  }

  wss = proc_mem_counters.WorkingSetSize;

  // Get session Id.
  result = ProcessIdToSessionId(process_id, &session_id);
  if (!result) {
    return WindowsError("os::process(): Failed to call ProcessIdToSessionId");
  }

  // Get Process CPU time.
  FILETIME create_filetime, exit_filetime, kernel_filetime, user_filetime;
  result = GetProcessTimes(
    safe_process_handle.get(),
    &create_filetime,
    &exit_filetime,
    &kernel_filetime,
    &user_filetime);
  if (!result) {
    return WindowsError("os::process(): Failed to call GetProcessTimes");
  }

  LARGE_INTEGER lKernelTime, lUserTime; // in 100 nanoseconds.
  lKernelTime.HighPart = kernel_filetime.dwHighDateTime;
  lKernelTime.LowPart = kernel_filetime.dwLowDateTime;
  lUserTime.HighPart = user_filetime.dwHighDateTime;
  lUserTime.LowPart = user_filetime.dwLowDateTime;

  system_time = lKernelTime.QuadPart / 10000000;
  user_time = lUserTime.QuadPart / 10000000;

  Try<Duration> utime = Duration::create(user_time);
  Try<Duration> stime = Duration::create(system_time);

  return Process(
    process_id,        // process id.
    parent_process_id, // parent process id.
    0,                 // group id.
    session_id,        // session id.
    Bytes(wss),        // wss.
    utime.isSome() ? utime.get() : Option<Duration>::none(),
    stime.isSome() ? stime.get() : Option<Duration>::none(),
    executable_filename,
    false);            // is not zombie process.
}


} // namespace os {


#endif // __STOUT_WINDOWS_OS_HPP__
