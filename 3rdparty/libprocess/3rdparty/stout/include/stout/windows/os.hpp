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

inline int pagesize()
{
  SYSTEM_INFO si = {0};
  GetSystemInfo(&si);
  return si.dwPageSize;
};

inline long cpu()
{
  return 4;
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
inline Try<std::set<pid_t>> pids(
    Option<pid_t> group,
    Option<pid_t> session) = delete;


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

} // namespace os {


#endif // __STOUT_WINDOWS_OS_HPP__
