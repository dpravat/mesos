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

using InputFileDescriptors = Subprocess::IO::InputFileDescriptors;
using OutputFileDescriptors = Subprocess::IO::OutputFileDescriptors;

namespace internal {

static void cleanup(
    const Future<Option<int>>& result,
    Promise<Option<int>>* promise,
    const Subprocess& subprocess)
{
  CHECK(!result.isPending());
  CHECK(!result.isDiscarded());

  if (result.isFailed()) {
    promise->fail(result.failure());
  } else {
    promise->set(result.get());
  }

  delete promise;
}

static void close(
    const InputFileDescriptors& stdinfds,
    const OutputFileDescriptors& stdoutfds,
    const OutputFileDescriptors& stderrfds)
{
  HANDLE handles[6] = {
    stdinfds.read, stdinfds.write.getOrElse(INVALID_HANDLE_VALUE),
    stdoutfds.read.getOrElse(INVALID_HANDLE_VALUE), stdoutfds.write,
    stderrfds.read.getOrElse(INVALID_HANDLE_VALUE), stderrfds.write
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
  char** argv,
  LPVOID environment,
  InputFileDescriptors stdinFds,
  OutputFileDescriptors stdoutFds,
  OutputFileDescriptors stderrFds)
{
  PROCESS_INFORMATION processInfo;
  STARTUPINFO startupInfo;

  ::ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
  ::ZeroMemory(&startupInfo, sizeof(STARTUPINFO));

  startupInfo.cb = sizeof(STARTUPINFO);
  startupInfo.hStdError = stderrFds.write;
  startupInfo.hStdOutput = stdoutFds.write;
  startupInfo.hStdInput = stdinFds.read;
  startupInfo.dwFlags |= STARTF_USESTDHANDLES;

  // See the `CreateProcess` MSDN page[1] for details on how `path` and
  // `args` work together in this case.
  //
  // [1] https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx
  BOOL createProcessResult = CreateProcess(
      (LPSTR)path.c_str(),  // Path of module to load[1].
      (LPSTR)argv,     // Command line arguments[1].
      NULL,                 // Default security attributes.
      NULL,                 // Default primary thread security attributes.
      TRUE,                 // Inherited parent process handles.
      0,                    // Default creation flags.
      environment,          // Array of environment variables[1].
      NULL,                 // Use parent's current directory.
      &startupInfo,         // STARTUPINFO pointer.
      &processInfo);        // PROCESS_INFORMATION pointer.

  if (!createProcessResult) {
    return WindowsError("CreateChildProcess: failed to call 'CreateProcess'");
  }

  // Close handles to child process/main thread and return child process PID
  ::CloseHandle(processInfo.hProcess);
  ::CloseHandle(processInfo.hThread);
  return processInfo.dwProcessId;
}

}  // namespace internal {

Subprocess::IO Subprocess::PIPE()
{
  return Subprocess::IO(
      []() -> Try<InputFileDescriptors> {
        HANDLE stdinHandle[2] = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };
        // Create STDIN pipe and set the 'write' component to not be inheritable.
        internal::CreatePipeHandles(stdinHandle);
        if (!::SetHandleInformation(&stdinHandle[1], HANDLE_FLAG_INHERIT, 0)) {
          return WindowsError("CreatePipes: Failed to call SetHandleInformation "
            "on stdin pipe");
        }

        InputFileDescriptors fds;
        fds.read = stdinHandle[0];
        fds.write = stdinHandle[1];
        return fds;
      },
      []() -> Try<OutputFileDescriptors> {
        HANDLE stdinHandle[2] = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };
        // Create STDIN pipe and set the 'read' component to not be inheritable.
        internal::CreatePipeHandles(stdinHandle);
        if (!::SetHandleInformation(&stdinHandle[0], HANDLE_FLAG_INHERIT, 0)) {
          return WindowsError("CreatePipes: Failed to call SetHandleInformation "
            "on stdin pipe");
        }

        OutputFileDescriptors fds;
        fds.read = stdinHandle[0];
        fds.write = stdinHandle[1];
        return fds;
      });
}


Subprocess::IO Subprocess::PATH(const string& path)
{
  return Subprocess::IO(
      [path]() -> Try<InputFileDescriptors> {
        HANDLE open = ::CreateFile(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (open == INVALID_HANDLE_VALUE) {
          return WindowsError("Failed to open '" + path + "'");
        }
        InputFileDescriptors fds;
        fds.read = open;
        return fds;
      },
      [path]() -> Try<OutputFileDescriptors> {
        HANDLE open = ::CreateFile(
            path.c_str(),
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (open == INVALID_HANDLE_VALUE) {
          return WindowsError("Failed to open '" + path + "'");
        }

        OutputFileDescriptors fds;
        fds.write = open;
        return fds;
      });
}


Subprocess::IO Subprocess::FD(int fd, IO::FDType type)
{
  return Subprocess::IO(
      [fd, type]() -> Try<InputFileDescriptors> {
        HANDLE prepared_handle = INVALID_HANDLE_VALUE;
        switch (type) {
          case IO::DUPLICATED:
          case IO::OWNED:
            // Extract handle from file descriptor.
            prepared_handle = (HANDLE)::_get_osfhandle(fd);
            if (prepared_handle == INVALID_HANDLE_VALUE) {
            return WindowsError("Failed to get handle of stdin file");
            }
            break;
          // NOTE: By not setting a default we leverage the compiler
          // errors when the enumeration is augmented to find all
          // the cases we need to provide.  Same for below.
        }

        InputFileDescriptors fds;
        fds.read = prepared_handle;
        return fds;
      },
      [fd, type]() -> Try<OutputFileDescriptors> {
        HANDLE prepared_handle = INVALID_HANDLE_VALUE;
        switch (type) {
        case IO::DUPLICATED:
        case IO::OWNED:
          // Extract handle from file descriptor.
          prepared_handle = (HANDLE)::_get_osfhandle(fd);
          if (prepared_handle == INVALID_HANDLE_VALUE) {
            return WindowsError("Failed to get handle of stdin file");
          }
            break;
          }

        OutputFileDescriptors fds;
        fds.write = prepared_handle;
        return fds;
      });
}



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
        pid_t(const lambda::function<int()>&)>>& _clone)
{
  // File descriptors for redirecting stdin/stdout/stderr.
  // These file descriptors are used for different purposes depending
  // on the specified I/O modes.
  // See `Subprocess::PIPE`, `Subprocess::PATH`, and `Subprocess::FD`.
  InputFileDescriptors stdinfds;
  OutputFileDescriptors stdoutfds;
  OutputFileDescriptors stderrfds;
  // Prepare the file descriptor(s) for stdin.
  Try<InputFileDescriptors> input = in.input();
  if (input.isError()) {
    return Error(input.error());
  }

  stdinfds = input.get();

  // Prepare the file descriptor(s) for stdout.
  Try<OutputFileDescriptors> output = out.output();
  if (output.isError()) {
    internal::close(stdinfds, stdoutfds, stderrfds);
    return Error(output.error());
  }

  stdoutfds = output.get();

  // Prepare the file descriptor(s) for stderr.
  output = err.output();
  if (output.isError()) {
    internal::close(stdinfds, stdoutfds, stderrfds);
    return Error(output.error());
  }

  stderrfds = output.get();

  // Prepare the arguments. If the user specifies the 'flags', we will
  // stringify them and append them to the existing arguments.
  if (flags.isSome()) {
    foreachpair (const string& name, const flags::Flag& flag, flags.get()) {
      Option<string> value = flag.stringify(flags.get());
      if (value.isSome()) {
        argv.push_back("--" + name + "=" + value.get());
      }
    }
  }

  // The real arguments that will be passed to 'os::execvpe'. We need
  // to construct them here before doing the clone as it might not be
  // async signal safe to perform the memory allocation.
  char** _argv = new char*[argv.size() + 1];
  for (int i = 0; i < argv.size(); i++) {
    _argv[i] = (char*) argv[i].c_str();
  }
  _argv[argv.size()] = NULL;

  // Like above, we need to construct the environment that we'll pass
  // to 'os::execvpe' as it might not be async-safe to perform the
  // memory allocations.
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
      _argv,
      (LPVOID)envp,
      stdinfds,
      stdoutfds,
      stderrfds);

  delete[] _argv;

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
    internal::close(stdinfds, stdoutfds, stderrfds);
    return error;
  }

  Subprocess process;
  process.data->pid = pid.get();

  // Close the handles that are created by this function. For pipes, we close
  // the child ends and store the parent ends (see thecode below).
  ::CloseHandle(stdinfds.read);
  ::CloseHandle(stdoutfds.write);
  ::CloseHandle(stderrfds.write);

  // If the mode is PIPE, store the parent side of the pipe so that
  // the user can communicate with the subprocess. Windows uses handles for all
  // of these, so we need to associate them to file descriptors first.
  int stdinFd =
    ::_open_osfhandle((intptr_t)stdinfds.write.getOrElse(INVALID_HANDLE_VALUE), _O_APPEND | _O_TEXT);

  int stdoutFd =
    ::_open_osfhandle((intptr_t)stdoutfds.read.getOrElse(INVALID_HANDLE_VALUE), _O_RDONLY | _O_TEXT);

  int stderrFd =
    ::_open_osfhandle((intptr_t)stderrfds.read.getOrElse(INVALID_HANDLE_VALUE), _O_RDONLY | _O_TEXT);

  process.data->in = stdinFd;
  process.data->out = stdinFd;
  process.data->err = stderrFd;

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
