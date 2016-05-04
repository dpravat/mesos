// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License

#ifndef __PROCESS_WINDOWS_SUBPROCESS_HPP__
#define __PROCESS_WINDOWS_SUBPROCESS_HPP__

#include <signal.h>

#include <string>

#include <glog/logging.h>

#include <process/subprocess.hpp>

#include <stout/error.hpp>
#include <stout/foreach.hpp>
#include <stout/option.hpp>
#include <stout/os.hpp>
#include <stout/try.hpp>

#include <stout/os/close.hpp>
#include <stout/os/environment.hpp>

using std::map;
using std::string;
using std::vector;


namespace process {

using InputFileDescriptors = Subprocess::IO::InputFileDescriptors;
using OutputFileDescriptors = Subprocess::IO::OutputFileDescriptors;

namespace internal {

// This function will invoke `os::close` on all specified file
// descriptors that are valid (i.e., not `None` and >= 0).
inline void close(
    const InputFileDescriptors& stdinfds,
    const OutputFileDescriptors& stdoutfds,
    const OutputFileDescriptors& stderrfds)
{
  HANDLE fds[6] = {
    stdinfds.read, stdinfds.write.getOrElse(INVALID_HANDLE_VALUE),
    stdoutfds.read.getOrElse(INVALID_HANDLE_VALUE), stdoutfds.write,
    stderrfds.read.getOrElse(INVALID_HANDLE_VALUE), stderrfds.write
  };

  foreach (HANDLE fd, fds) {
    if (fd >= 0) {
      os::close(fd);
    }
  }
}


// Creates a NULL-terminated array of NULL-terminated strings that will be
// passed to `CreateProcess` as the `lpEnvironment` argument, as described by
// MSDN[1]. This array needs to be sorted in alphabetical order, but the `map`
// already takes care of that. Note that this function does not handle Unicode
// environments, so it should not be used in conjunction with the
// `CREATE_UNICODE_ENVIRONMENT` flag.
//
// This function allocates a block of memory via the `new` operator. It is the
// responsibility of the caller to deallocate this memory by calling `delete`.
//
// Per MSDN[1], the maximum size of the ASCII environment can be 32767 bytes.
// In cases where the constructed environment block would be larger than this
// limit, this function does not allocate any memory and instead returns `NULL`.
//
// [1] https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx
inline char* createProcessEnvironment(const map<string, string>& env)
{
  // Per MSDN[1], the maximum size of the ASCII environment can be 32767 bytes.
  // This constraint is removed for Unicode.
  const static int max_env_size = 32767;

  // Determine the size of buffer needed first. For each key/value pair, we
  // leave space for 2 additional characters: one for the null terminator, and
  // one for the `=` sign.
  uint64_t totalBytes = 0;
  foreachpair(const std::string& key, const std::string& value, env) {
    totalBytes += key.size() + value.size() + 2;
  }

  // One more character for the final, extra NULL character.
  totalBytes++;

  if (totalBytes > max_env_size) {
    return NULL;
  }

  char* environment = new char[totalBytes];
  size_t index = 0;
  // For each key/value pair, create a string representing the definition of
  // an environment variable: something like `key1=value1\0`. Then, copy that
  // whole string, including null terminator, to `environment` array.
  foreachpair(const std::string& key, const std::string& value, env) {
    const string assignment = key + "=" + value;
    strcpy_s(environment + index, totalBytes - index, assignment.c_str());
    index += assignment.size() + 1;
  }

  // NULL-terminate the entire block.
  environment[index] = 0;
  return environment;
}


inline Try<PROCESS_INFORMATION> createChildProcess(
    const string& path,
    const vector<string>& argv,
    const Option<map<string, string>>& environment,
    const InputFileDescriptors stdinfds,
    const OutputFileDescriptors stdoutfds,
    const OutputFileDescriptors stderrfds)
{
  // Construct the environment that will be passed to `CreateProcess`.
  std::unique_ptr<char> env;
  if (environment.isSome()) {
    env = std::unique_ptr<char>(createProcessEnvironment(environment.get()));
  }

  PROCESS_INFORMATION processInfo;
  STARTUPINFO startupInfo;

  ::ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
  ::ZeroMemory(&startupInfo, sizeof(STARTUPINFO));

  // Hook up the `stdin`/`stdout`/`stderr` pipes and use the
  // `STARTF_USESTDHANDLES` flag to instruct the child to use them[1]. A more
  // user-friendly example can be found in [2].
  //
  // [1] https://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx
  // [2] https://msdn.microsoft.com/en-us/library/windows/desktop/ms682499(v=vs.85).aspx
  startupInfo.cb = sizeof(STARTUPINFO);
  startupInfo.hStdError = stderrfds.write;
  startupInfo.hStdOutput = stdoutfds.write;
  startupInfo.hStdInput = stdinfds.read;
  startupInfo.dwFlags |= STARTF_USESTDHANDLES;

  // Build child process arguments (as a NULL-terminated string).
  char* arguments = NULL;
  char* argumentsEscaped = NULL;
  if (!argv.empty()) {
    // Start the `arguments` string with a space, since `CreateProcess` will
    // just append it to the `lpCommandLine` argument.
    size_t argLength = 0;
    foreach(string arg, argv) {
      argLength += arg.size() + 1;  // extra char for ' ' or trailing NULL.
    }

    arguments = new char[argLength];
    // arguments[0] = ' ';
    size_t index = 0;
    foreach(string arg, argv) {
      strncpy(arguments + index, arg.c_str(), arg.size());
      index += arg.size();
      arguments[index++] = ' ';
    }

    // NULL-terminate the arguments string.
    arguments[index - 1] = '\0';
    // Aditional size
    int count = std::count(arguments, arguments + argLength, '\"');
    argumentsEscaped = new char[argLength + count];
    char* buffer = argumentsEscaped;
    std::for_each(arguments, arguments + argLength, [&buffer](char c)
        { if (c == '\"') *buffer++ = '\\'; *buffer++ = c; }
      );
  }

  // See the `CreateProcess` MSDN page[1] for details on how `path` and
  // `args` work together in this case.
  //
  // [1] https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx
  BOOL createProcessResult = CreateProcess(
      // TODO(hausdorff): Figure out how to write this part.
      // (LPSTR)path.c_str(),  // Path of module to load[1].
      NULL,
      (LPSTR)argumentsEscaped, // Command line arguments[1].
      NULL,                    // Default security attributes.
      NULL,                    // Default primary thread security attributes.
      TRUE,                    // Inherited parent process handles.
      0,                       // Normal thread priority.
      (LPVOID)env.get(),       // Array of environment variables[1].
      NULL,                    // Use parent's current directory.
      &startupInfo,            // STARTUPINFO pointer.
      &processInfo);           // PROCESS_INFORMATION pointer.

  if (arguments != NULL) {
    delete arguments;
  }

  if (!createProcessResult) {
    return WindowsError("createChildProcess: failed to call 'CreateProcess'");
  }

  return processInfo;
}

}  // namespace internal {
}  // namespace process {

#endif // __PROCESS_WINDOWS_SUBPROCESS_HPP__
