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

using std::array;
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
    const Subprocess& subprocess,
    HANDLE process)
{
  CHECK(!result.isPending());
  CHECK(!result.isDiscarded());

  if (result.isFailed()) {
    promise->fail(result.failure());
  } else {
    promise->set(result.get());
  }

  delete promise;
  ::CloseHandle(process);
}


static void close(
    const InputFileDescriptors& stdinfds,
    const OutputFileDescriptors& stdoutfds,
    const OutputFileDescriptors& stderrfds)
{
  const HANDLE handles[6] = {
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


static Try<HANDLE> duplicateHandle(const HANDLE handle)
{
  HANDLE duplicate = INVALID_HANDLE_VALUE;

  // TODO(anaparu): Do we need to scope the duplicated handle
  // to the child process?
  BOOL result = ::DuplicateHandle(
      ::GetCurrentProcess(),  // Source process == current.
      handle,                 // Handle to duplicate.
      ::GetCurrentProcess(),  // Target process == current.
      &duplicate,
      0,                      // Ignored (DUPLICATE_SAME_ACCESS).
      TRUE,                   // Inheritable handle.
      DUPLICATE_SAME_ACCESS); // Same access level as source.

  if (!result) {
    return WindowsError("Failed to duplicate handle of stdin file");
  } else {
    return duplicate;
  }
}


// Returns either the file descriptor associated to the Windows handle, or
// `Nothing` if the handle is invalid.
static Option<int> getFileDescriptorFromHandle(
    const Option<HANDLE>& handle,
    const int flags)
{
  int fd = ::_open_osfhandle(
      reinterpret_cast<intptr_t>(handle.getOrElse(INVALID_HANDLE_VALUE)),
      flags);

  return fd > 0 ? Option<int>(fd) : None();
}


static Try<HANDLE> getHandleFromFileDescriptor(int fd)
{
  // Extract handle from file descriptor.
  const HANDLE handle = reinterpret_cast<HANDLE>(::_get_osfhandle(fd));
  if (handle == INVALID_HANDLE_VALUE) {
    return WindowsError("Failed to get `HANDLE` for file descriptor");
  } else {
    return handle;
  }
}


static Try<HANDLE> getHandleFromFileDescriptor(
    const int fd,
    const Subprocess::IO::FDType type)
{
  Try<HANDLE> handle = getHandleFromFileDescriptor(fd);
  if (handle.isError()) {
    return Error(handle.error());
  }

  switch (type) {
    case Subprocess::IO::DUPLICATED: {
      const Try<HANDLE> duplicate = duplicateHandle(handle.get());

      if (duplicate.isError()) {
        return Error(duplicate.error());
      }

      handle = duplicate;
    }
    case Subprocess::IO::OWNED:
      return handle;

    // NOTE: By not setting a default we leverage the compiler
    // errors when the enumeration is augmented to find all
    // the cases we need to provide. Same for below.
  }
}


// TODO(hausdorff): Rethink name here, write a comment about this function.
static Try<HANDLE> createIoPath(const string& path, DWORD accessFlags)
{
  // The `TRUE` in the last field makes this duplicate handle inheritable.
  SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
  const HANDLE handle = ::CreateFile(
      path.c_str(),
      accessFlags,
      FILE_SHARE_READ,
      &sa,
      CREATE_NEW,
      FILE_ATTRIBUTE_NORMAL,
      NULL);

  if (handle == INVALID_HANDLE_VALUE) {
    return WindowsError("Failed to open '" + path + "'");
  }

  return handle;
}


static Try<HANDLE> createInputFile(const string& path)
{
  // Get a handle to the `stdin` file. Use `GENERIC_READ` and
  // `FILE_SHARE_READ` to make the handle read/only (as `stdin` should
  // be), but allow others to read from the same file.
  return createIoPath(path, GENERIC_READ);
}


static Try<HANDLE> createOutputFile(const string& path)
{
  // Get a handle to the `stdout` file. Use `GENERIC_WRITE` to make the
  // handle writeable (as `stdout` should be) and do not allow others to
  // share the file.
  return createIoPath(path, GENERIC_WRITE);
}


// Opens an inheritable pipe[1] represented as a pair of file handles. On
// success, the first handle returned recieves the 'read' handle of the pipe,
// while the second receives the 'write' handle. The pipe handles can then be
// passed to a child process, as exemplified in [2].
//
// [1] https://msdn.microsoft.com/en-us/library/windows/desktop/aa379560(v=vs.85).aspx
// [2] https://msdn.microsoft.com/en-us/library/windows/desktop/ms682499(v=vs.85).aspx
static Try<array<HANDLE, 2>> createPipeHandles()
{
  // The `TRUE` in the last field makes this duplicate handle inheritable.
  SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
  array<HANDLE, 2> handles{ INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };

  if (!::CreatePipe(&handles[0], &handles[1], &sa, 0)) {
    return WindowsError("createPipeHandles: could not create pipe");
  }

  return handles;
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
static char* createProcessEnvironment(const map<string, string>& env)
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


Try<PROCESS_INFORMATION> createChildProcess(
    const string& path,
    const vector<string>& argv,
    const char* environment,
    InputFileDescriptors stdinFds,
    OutputFileDescriptors stdoutFds,
    OutputFileDescriptors stderrFds)
{
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
  startupInfo.hStdError = stderrFds.write;
  startupInfo.hStdOutput = stdoutFds.write;
  startupInfo.hStdInput = stdinFds.read;
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
      CREATE_SUSPENDED,        // Primary thread suspended until we start it.
      (LPVOID)environment,     // Array of environment variables[1].
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


Subprocess::IO Subprocess::PIPE()
{
  return Subprocess::IO(
      []() -> Try<InputFileDescriptors> {
        const Try<array<HANDLE, 2>> handles = internal::createPipeHandles();
        if (handles.isError()) {
          return Error(handles.error());
        }

        // Create STDIN pipe and set the 'write' component to not be
        // inheritable.
        if (!::SetHandleInformation(handles.get()[1], HANDLE_FLAG_INHERIT, 0)) {
          return WindowsError(
              "PIPE: Failed to call SetHandleInformation on stdin pipe");
        }

        InputFileDescriptors fds;
        fds.read = handles.get()[0];
        fds.write = handles.get()[1];
        return fds;
      },
      []() -> Try<OutputFileDescriptors> {
        const Try<array<HANDLE, 2>> handles = internal::createPipeHandles();
        if (handles.isError()) {
          return Error(handles.error());
        }

        // Create OUT pipe and set the 'read' component to not be inheritable.
        if (!::SetHandleInformation(handles.get()[0], HANDLE_FLAG_INHERIT, 0)) {
          return WindowsError(
              "PIPE: Failed to call SetHandleInformation on out pipe");
        }

        OutputFileDescriptors fds;
        fds.read = handles.get()[0];
        fds.write = handles.get()[1];
        return fds;
      });
}


Subprocess::IO Subprocess::PATH(const string& path)
{
  return Subprocess::IO(
      [path]() -> Try<InputFileDescriptors> {
        const Try<HANDLE> inHandle = internal::createInputFile(path);

        if (inHandle.isError()) {
          return Error(inHandle.error());
        }

        InputFileDescriptors inDescriptors;
        inDescriptors.read = inHandle.get();
        return inDescriptors;
      },
      [path]() -> Try<OutputFileDescriptors> {
        const Try<HANDLE> outHandle = internal::createOutputFile(path);

        if (outHandle.isError()) {
          return Error(outHandle.error());
        }

        OutputFileDescriptors outDescriptors;
        outDescriptors.write = outHandle.get();
        return outDescriptors;
      });
}


Subprocess::IO Subprocess::FD(int fd, IO::FDType type)
{
  return Subprocess::IO(
      [fd, type]() -> Try<InputFileDescriptors> {
        const Try<HANDLE> inHandle =
          internal::getHandleFromFileDescriptor(fd, type);

        if (inHandle.isError()) {
          return Error(inHandle.error());
        }

        InputFileDescriptors fds;
        fds.read = inHandle.get();
        return fds;
      },
      [fd, type]() -> Try<OutputFileDescriptors> {
        const Try<HANDLE> outHandle =
          internal::getHandleFromFileDescriptor(fd, type);

        if (outHandle.isError()) {
          return Error(outHandle.error());
        }

        OutputFileDescriptors fds;
        fds.write = outHandle.get();
        return fds;
      });
}


// TODO(hausdorff): use RAII handles
Try<Subprocess> subprocess(
    const string& path,
    vector<string> argv,
    const Subprocess::IO& in,
    const Subprocess::IO& out,
    const Subprocess::IO& err,
    const Setsid setsid,
    const Option<flags::FlagsBase>& flags,
    const Option<map<string, string>>& environment,
    const Option<lambda::function<
        pid_t(const lambda::function<int()>&)>>& _clone,
    const vector<Subprocess::Hook>& parent_hooks,
    const Option<string>& working_directory,
    const Watchdog watchdog)
{
  // File descriptors for redirecting stdin/stdout/stderr.
  // These file descriptors are used for different purposes depending
  // on the specified I/O modes.
  // See `Subprocess::PIPE`, `Subprocess::PATH`, and `Subprocess::FD`.
  //
  // All these handles need to be closed before exiting the function on an
  // error condition. While RAII handles would make the code cleaner, we chose
  // to use internal::close() instead on all error paths. This is because on
  // success some of the handles (stdin-write, stdout-read, stderr-read) need
  // to remain open for the child process to use.
  InputFileDescriptors stdinfds;
  OutputFileDescriptors stdoutfds;
  OutputFileDescriptors stderrfds;

  // Prepare the file descriptor(s) for stdin.
  const Try<InputFileDescriptors> input = in.input();
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
      const Option<string> value = flag.stringify(flags.get());
      if (value.isSome()) {
        argv.push_back("--" + name + "=" + value.get());
      }
    }
  }

  // Construct the environment that will be passed to `CreateProcess`.
  std::unique_ptr<char> env;
  if (environment.isSome()) {
    env = std::unique_ptr<char>(
        internal::createProcessEnvironment(environment.get()));
  }

  // Create the child process and pass the stdin/stdout/stderr handles.
  Try<PROCESS_INFORMATION> processInformation = internal::createChildProcess(
      path,
      argv,
      env.get(),
      stdinfds,
      stdoutfds,
      stderrfds);

  if (processInformation.isError()) {
    internal::close(stdinfds, stdoutfds, stderrfds);
    return Error("Could not launch child process" + processInformation.error());
  }

  if (processInformation.get().dwProcessId == -1) {
    // Save the errno as 'close' below might overwrite it.
    ErrnoError error("Failed to clone");
    internal::close(stdinfds, stdoutfds, stderrfds);
    return error;
  }

  Subprocess process;
  process.data->pid = processInformation.get().dwProcessId;

  // TODO(hausdorff): Investigate if handles need to be closed here.
  //
  // Close the handles that are created by this function. For pipes, we close
  // the child ends and store the parent ends (see thecode below).
  ::CloseHandle(stdinfds.read);
  ::CloseHandle(stdoutfds.write);
  ::CloseHandle(stderrfds.write);

  // If the mode is PIPE, store the parent side of the pipe so that
  // the user can communicate with the subprocess. Windows uses handles for all
  // of these, so we need to associate them to file descriptors first.
  process.data->in = internal::getFileDescriptorFromHandle(
      stdinfds.write, _O_APPEND | _O_TEXT);

  process.data->out = internal::getFileDescriptorFromHandle(
      stdoutfds.read, _O_RDONLY | _O_TEXT);

  process.data->err = internal::getFileDescriptorFromHandle(
      stdoutfds.read, _O_RDONLY | _O_TEXT);

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
    .onAny(
        lambda::bind(
            internal::cleanup,
            lambda::_1,
            promise,
            process,
            processInformation.get().hProcess));

  ResumeThread(processInformation.get().hThread);
  ::CloseHandle(processInformation.get().hThread);
  return process;
}

}  // namespace process {
