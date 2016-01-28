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

#include <stout/os/raw/environment.hpp>
#include <stout/os/os.hpp>
#include <stout/os/config.hpp>

#define WNOHANG 0
#define hstrerror() ("")
#define SIGPIPE 100

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

}

/*
// Unsets the value associated with the specified key in the set of
// environment variables.
inline void unsetenv(const std::string& key)
{
  UNIMPLEMENTED;
}


// Executes a command by calling "/bin/sh -c <command>", and returns
// after the command has been completed. Returns 0 if succeeds, and
// return -1 on error (e.g., fork/exec/waitpid failed). This function
// is async signal safe. We return int instead of returning a Try
// because Try involves 'new', which is not async signal safe.
inline int system(const std::string& command)
{
  UNIMPLEMENTED;
}


// This function is a portable version of execvpe ('p' means searching
// executable from PATH and 'e' means setting environments). We add
// this function because it is not available on all systems.
//
// NOTE: This function is not thread safe. It is supposed to be used
// only after fork (when there is only one thread). This function is
// async signal safe.
inline int execvpe(const char* file, char** argv, char** envp)
{
  UNIMPLEMENTED;
}


inline Try<Nothing> chown(
    uid_t uid,
    gid_t gid,
    const std::string& path,
    bool recursive)
{
  UNIMPLEMENTED;
}


inline Try<Nothing> chmod(const std::string& path, int mode)
{
  UNIMPLEMENTED;
}


inline Try<Nothing> chroot(const std::string& directory)
{
  UNIMPLEMENTED;
}


inline Try<Nothing> mknod(
    const std::string& path,
    mode_t mode,
    dev_t dev)
{
  UNIMPLEMENTED;
}


inline Result<uid_t> getuid(const Option<std::string>& user = None())
{
  UNIMPLEMENTED;
}


inline Result<gid_t> getgid(const Option<std::string>& user = None())
{
  UNIMPLEMENTED;
}


inline Try<Nothing> su(const std::string& user)
{
  UNIMPLEMENTED;
}


inline Result<std::string> user(Option<uid_t> uid = None())
{
  UNIMPLEMENTED;
}
// Returns the list of files that match the given (shell) pattern.
inline Try<std::list<std::string>> glob(const std::string& pattern)
{
UNIMPLEMENTED;
}
*/

// Suspends execution for the given duration.
inline Try<Nothing> sleep(const Duration& duration)
{
  return Nothing();
}




// Returns the total number of cpus (cores).
inline Try<long> cpus()
{
  return 4;
}


// Returns load struct with average system loads for the last
// 1, 5 and 15 minutes respectively.
// Load values should be interpreted as usual average loads from
// uptime(1).
inline Try<Load> loadavg()
{
  return Load();
}


// Returns the total size of main and free memory.
inline Try<Memory> memory()
{
  return Memory();
}


// Return the system information.
inline Try<UTSInfo> uname()
{
  return UTSInfo();
}


inline Try<std::list<Process>> processes()
{
  return std::list<Process>();
}

inline size_t recv(int sockfd, void *buf, size_t len, int flags) {
  return ::recv(sockfd, (char*)buf, len, flags);
}

inline int setsockopt(int socket, int level, int option_name,
       const void *option_value, socklen_t option_len) {
  return ::setsockopt(socket, level, option_name, (const char*)option_value, option_len);
}

inline int getsockopt(int socket, int level, int option_name,
  void* option_value, socklen_t* option_len) {
  return ::getsockopt(socket, level, option_name, (char*)option_value, option_len);
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

#ifdef _WINDOWS_

inline struct tm* gmtime_r(const time_t *timep, struct tm *result)
{
  if (gmtime_s(result, timep))
  {
    return result;
  }

  return NULL;
}

#else // ​_WINDOWS_

inline auto gmtime_r(const time_t *timep, struct tm *result) {
  return ::gmtime_r(timep, result);
}

#endif // ​_WINDOWS_

inline pid_t waitpid(pid_t pid, int *status, int options)
{
    return 0;
}

namespace libraries {

  // Returns the full library name by adding prefix and extension to
  // library name.
  inline std::string expandName(const std::string& libraryName)
  {
    const char* prefix = "lib";
    const char* extension =
#ifdef __APPLE__
      ".dylib";
#else
      ".so";
#endif

    return prefix + libraryName + extension;
  }


  // Returns the current value of LD_LIBRARY_PATH environment variable.
  inline std::string paths()
  {
    const char* environmentVariable =
#ifdef __APPLE__
      "DYLD_LIBRARY_PATH";
#else
      "LD_LIBRARY_PATH";
#endif
    const Option<std::string> path = getenv(environmentVariable);
    return path.isSome() ? path.get() : std::string();
  }


  // Updates the value of LD_LIBRARY_PATH environment variable.
  inline void setPaths(const std::string& newPaths)
  {
    const char* environmentVariable =
#ifdef __APPLE__
      "DYLD_LIBRARY_PATH";
#else
      "LD_LIBRARY_PATH";
#endif
    os::setenv(environmentVariable, newPaths);
  }


  // Append newPath to the current value of LD_LIBRARY_PATH environment
  // variable.
  inline void appendPaths(const std::string& newPaths)
  {
    if (paths().empty()) {
      setPaths(newPaths);
    }
    else {
      setPaths(paths() + ":" + newPaths);
    }
  }

} // namespace libraries {

inline auto access(const std::string& fileName, int accessMode) ->
decltype(_access(fileName.c_str(), accessMode))
{
  return _access(fileName.c_str(), accessMode);
}
} // namespace os {


#endif // __STOUT_WINDOWS_OS_HPP__
