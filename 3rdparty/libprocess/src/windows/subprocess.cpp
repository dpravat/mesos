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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include <string>

#include <glog/logging.h>

#include <process/future.hpp>
#include <process/reap.hpp>
#include <process/subprocess.hpp>

#include <stout/error.hpp>
#include <stout/lambda.hpp>
#include <stout/foreach.hpp>
#include <stout/option.hpp>
#include <stout/os.hpp>
#include <stout/os/strerror.hpp>
#include <stout/strings.hpp>
#include <stout/try.hpp>
#include <stout/unreachable.hpp>
#include <stout/windows.hpp>

using std::map;
using std::string;
using std::vector;

namespace process {
namespace internal {

extern void cleanup(
    const Future<Option<int>>& result,
    Promise<Option<int>>* promise,
    const Subprocess& subprocess);

static void close(
    HANDLE stdinHandle[2],
    HANDLE stdoutHandle[2],
    HANDLE stderrHandle[2])
{
  HANDLE handles[6] = {
    stdinHandle[0], stdinHandle[1],
    stdoutHandle[0], stdoutHandle[1],
    stderrHandle[0], stderrHandle[1]
  };

  foreach(HANDLE handle, handles) {
    if (handle != INVALID_HANDLE_VALUE) {
      ::CloseHandle(handle);
    }
  }
}

Try<Nothing> CreatePipeHandles(HANDLE handles[2])
{
  SECURITY_ATTRIBUTES securityAttr;
  securityAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
  securityAttr.bInheritHandle = TRUE;
  securityAttr.lpSecurityDescriptor = NULL;

  if (!::CreatePipe(&handles[0], &handles[1], &securityAttr, 0)) {
    return WindowsError("CreatePipeHandles: could not create pipe");
  }

  return Nothing();
}

Try<pid_t> CreateChildProcess(
  const string& path,
  vector<string> argv,
  LPVOID environment,
  HANDLE* stdinPipe,
  HANDLE* stdoutPipe,
  HANDLE* stderrPipe)
{
  PROCESS_INFORMATION processInfo;
  STARTUPINFO startupInfo;

  ::ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
  ::ZeroMemory(&startupInfo, sizeof(STARTUPINFO));

  startupInfo.cb = sizeof(STARTUPINFO);
  startupInfo.hStdError = stderrPipe[1];
  startupInfo.hStdOutput = stdoutPipe[1];
  startupInfo.hStdInput = stdinPipe[0];
  startupInfo.dwFlags |= STARTF_USESTDHANDLES;

  // Build child process arguments (as a NULL-terminated string).
  size_t argLength = 0;
  foreach(string arg, argv) {
    argLength += arg.size() + 1;  // extra char for 'space' or NULL.
  }

  char *arguments = new char[argLength];
  size_t index = 0;
  foreach(string arg, argv) {
    strncpy(arguments + index, arg.c_str(), arg.size());
    index += arg.size();
    arguments[index] = ' ';
  }

  // NULL-terminate the arguments string.
  arguments[index] = '\0';

  // See the `CreateProcess` MSDN page[1] for details on how `path` and
  // `args` work together in this case.
  //
  // [1] https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx
  BOOL createProcessResult = CreateProcess(
      (LPSTR)path.c_str(),  // Path of module to load[1].
      (LPSTR)arguments,     // Command line arguments[1].
      NULL,                 // Default security attributes.
      NULL,                 // Default primary thread security attributes.
      TRUE,                 // Inherited parent process handles.
      0,                    // Default creation flags.
      environment,          // Array of environment variables[1].
      NULL,                 // Use parent's current directory.
      &startupInfo,         // STARTUPINFO pointer.
      &processInfo);        // PROCESS_INFORMATION pointer.

  // Release memory taken by the `arguments` string.
  delete arguments;

  if (!createProcessResult) {
    return WindowsError("CreateChildProcess: failed to call 'CreateProcess'");
  }

  // Close handles to child process/main thread and return child process PID
  ::CloseHandle(processInfo.hProcess);
  ::CloseHandle(processInfo.hThread);
  return processInfo.dwProcessId;
}
} // namespace internal {

// TODO(alexnaparu): use RAII handles
Try<Subprocess> subprocess(
    const string& path,
    vector<string> argv,
    const Subprocess::IO& in,
    const Subprocess::IO& out,
    const Subprocess::IO& err,
    const Option<flags::FlagsBase>& flags,
    const Option<map<string, string>>& environment,
    const Option<lambda::function<int()>>& setup,
    const Option<lambda::function<
        pid_t(const lambda::function<int()>&)>>& _clone,
    const std::vector<Subprocess::Hook>& parent_hooks)
{
  // File descriptors for redirecting stdin/stdout/stderr. These file
  // descriptors are used for different purposes depending on the
  // specified I/O modes. If the mode is PIPE, the two file
  // descriptors represent two ends of a pipe. If the mode is PATH or
  // FD, only one of the two file descriptors is used. Our protocol
  // here is that index 0 is always for reading, and index 1 is always
  // for writing (similar to the pipe semantics).
  HANDLE stdinHandle[2] = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };
  HANDLE stdoutHandle[2] = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };
  HANDLE stderrHandle[2] = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };

  // Prepare the file descriptor(s) for stdin.
  switch (in.mode) {
    case Subprocess::IO::FD: {
      // Extract handle from file descriptor.
      stdinHandle[0] = (HANDLE)::_get_osfhandle(in.fd.get());
      if (stdinHandle[0] == INVALID_HANDLE_VALUE) {
        return WindowsError("Failed to get handle of stdin file");
      }
      break;
    }
    case Subprocess::IO::PIPE: {
      // Create STDIN pipe and set the 'write' component to not be inheritable.
      internal::CreatePipeHandles(stdinHandle);
      if (!::SetHandleInformation(&stdinHandle[1], HANDLE_FLAG_INHERIT, 0)) {
        return WindowsError("CreatePipes: Failed to call SetHandleInformation "
          "on stdin pipe");
      }
      break;
    }
    case Subprocess::IO::PATH: {
      stdinHandle[0] = ::CreateFile(
          in.path.get().c_str(),
          GENERIC_READ,
          FILE_SHARE_READ,
          NULL,
          CREATE_NEW,
          FILE_ATTRIBUTE_NORMAL,
          NULL);

      if (stdinHandle[0] == INVALID_HANDLE_VALUE) {
        return WindowsError("Failed to open '" + in.path.get() + "'");
      }
      break;
    }
    default:
      UNREACHABLE();
  }

  // Prepare the file descriptor(s) for stdout.
  switch (out.mode) {
    case Subprocess::IO::FD: {
      // Extract handle from file descriptor.
      stdoutHandle[1] = (HANDLE)::_get_osfhandle(out.fd.get());
      if (stdoutHandle[1] == INVALID_HANDLE_VALUE) {
        return WindowsError("Failed to get handle of stdout file");
      }
      break;
    }
    case Subprocess::IO::PIPE: {
      // Create STDOUT pipe and set the 'read' component to not be inheritable.
      internal::CreatePipeHandles(stdoutHandle);
      if (!::SetHandleInformation(&stdoutHandle[0], HANDLE_FLAG_INHERIT, 0)) {
        return WindowsError("CreatePipes: Failed to call SetHandleInformation "
          "on stdout pipe");
      }
      break;
    }
    case Subprocess::IO::PATH: {
      stdoutHandle[1] = ::CreateFile(
          in.path.get().c_str(),
          GENERIC_WRITE,
          0,
          NULL,
          CREATE_ALWAYS,
          FILE_ATTRIBUTE_NORMAL,
          NULL);

      if (stdoutHandle[1] == INVALID_HANDLE_VALUE) {
        return WindowsError("Failed to open '" + in.path.get() + "'");
      }
      break;
    }
    default:
      UNREACHABLE();
  }

  // Prepare the file descriptor(s) for stderr.
  switch (err.mode) {
    case Subprocess::IO::FD: {
      // Extract handle from file descriptor.
      stderrHandle[1] = (HANDLE)::_get_osfhandle(err.fd.get());
      if (stderrHandle[1] == INVALID_HANDLE_VALUE) {
        return WindowsError("Failed to get handle of stderr file");
      }
      break;
    }
    case Subprocess::IO::PIPE: {
      // Create STDERR pipe and set the 'read' component to not be inheritable.
      internal::CreatePipeHandles(stderrHandle);
      if (!::SetHandleInformation(&stderrHandle[0], HANDLE_FLAG_INHERIT, 0)) {
        return WindowsError("CreatePipes: Failed to call SetHandleInformation "
          "on stderr pipe");
      }
      break;
    }
    case Subprocess::IO::PATH: {
      stderrHandle[1] = ::CreateFile(
          in.path.get().c_str(),
          GENERIC_WRITE,
          0,
          NULL,
          CREATE_NEW,
          FILE_ATTRIBUTE_NORMAL,
          NULL);

      if (stderrHandle[1] == INVALID_HANDLE_VALUE) {
        return WindowsError("Failed to open '" + in.path.get() + "'");
      }
      break;
    }
    default:
      UNREACHABLE();
  }

  // Build environment
  char** envp = os::raw::environment();

  if (environment.isSome()) {
    // According to MSDN[1], the `lpEnvironment` argument of `CreateProcess`
    // takes a null-terminated array of null-terminated strings. Each of these
    // strings must follow the `name=value\0` format.
    envp = new char*[environment.get().size() + 1];

    size_t index = 0;
    foreachpair(const string& key, const string& value, environment.get()) {
      string entry = key + "=" + value;
      envp[index] = new char[entry.size() + 1];
      strncpy(envp[index], entry.c_str(), entry.size() + 1);
      ++index;
    }

    envp[index] = NULL;
  }

  // Create the child process and pass the stdin/stdout/stderr handles.
  Try<pid_t> pid = internal::CreateChildProcess(
      path,
      argv,
      (LPVOID)envp,
      stdinHandle,
      stdoutHandle,
      stderrHandle);

  // Need to delete 'envp' if we had environment variables passed to
  // us and we needed to allocate the space.
  if (environment.isSome()) {
    CHECK_NE(os::raw::environment(), envp);
    delete[] envp;
  }

  if (pid.isError()) {
    return Error("Could not launch child process" + pid.error());
  }

  if (pid.get() == -1) {
    // Save the errno as 'close' below might overwrite it.
    ErrnoError error("Failed to clone");
    internal::close(stdinHandle, stdoutHandle, stderrHandle);
    return error;
  }

  Subprocess process;
  process.data->pid = pid.get();

  // Close the handles that are created by this function. For pipes, we close
  // the child ends and store the parent ends (see thecode below).
  ::CloseHandle(stdinHandle[0]);  // os::close(stdinHandle[0]);
  ::CloseHandle(stdoutHandle[1]); // os::close(stdoutHandle[1]);
  ::CloseHandle(stderrHandle[1]); // os::close(stderrHandle[1]);

  // If the mode is PIPE, store the parent side of the pipe so that
  // the user can communicate with the subprocess. Windows uses handles for all
  // of these, so we need to associate them to file descriptors first.
  int stdinFd =
    ::_open_osfhandle((intptr_t)stdinHandle[1], _O_APPEND | _O_TEXT);

  int stdoutFd =
    ::_open_osfhandle((intptr_t)stdoutHandle[0], _O_RDONLY | _O_TEXT);

  int stderrFd =
    ::_open_osfhandle((intptr_t)stderrHandle[0], _O_RDONLY | _O_TEXT);

  if (in.mode == Subprocess::IO::PIPE) {
    process.data->in = stdinFd;
  }
  if (out.mode == Subprocess::IO::PIPE) {
    process.data->out = stdoutFd;
  }
  if (err.mode == Subprocess::IO::PIPE) {
    process.data->err = stderrFd;
  }

  // Rather than directly exposing the future from process::reap, we
  // must use an explicit promise so that we can ensure we can receive
  // the termination signal. Otherwise, the caller can discard the
  // reap future, and we will not know when it is safe to close the
  // file descriptors.
  Promise<Option<int>>* promise = new Promise<Option<int>>();
  process.data->status = promise->future();

  // We need to bind a copy of this Subprocess into the onAny callback
  // below to ensure that we don't close the file descriptors before
  // the subprocess has terminated (i.e., because the caller doesn't
  // keep a copy of this Subprocess around themselves).
  process::reap(process.data->pid)
    .onAny(lambda::bind(internal::cleanup, lambda::_1, promise, process));

  return process;
}

}  // namespace process {
