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

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef __WINDOWS__
#include <unistd.h>
#endif // __WINDOWS__
#include <sys/types.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif // __linux__
#include <sys/types.h>

#include <string>

#include <glog/logging.h>

#include <process/future.hpp>
#include <process/reap.hpp>
#include <process/subprocess.hpp>

// NOTE: This comes after `subprocess.hpp` because C++ doesn't allow forward
// declarations of nested classes.
#ifndef __WINDOWS__
#include <process/posix/subprocess.hpp>
#else
#include <process/windows/subprocess.hpp>
#endif // __WINDOWS__

#include <stout/error.hpp>
#include <stout/lambda.hpp>
#include <stout/foreach.hpp>
#include <stout/option.hpp>
#include <stout/os.hpp>
#include <stout/os/strerror.hpp>
#include <stout/strings.hpp>
#include <stout/try.hpp>
#include <stout/unreachable.hpp>

using std::map;
using std::string;
using std::vector;

namespace process {

using InputFileDescriptors = Subprocess::IO::InputFileDescriptors;
using OutputFileDescriptors = Subprocess::IO::OutputFileDescriptors;


Subprocess::Hook::Hook(
    const lambda::function<Try<Nothing>(pid_t)>& _parent_callback)
  : parent_callback(_parent_callback) {}

namespace internal {

static void cleanup(
    const Future<Option<int>>& result,
    Promise<Option<int>>* promise,
    const Subprocess& subprocess,
    const lambda::function<void()>& post_cleanup_hook)
{
  CHECK(!result.isPending());
  CHECK(!result.isDiscarded());

  if (result.isFailed()) {
    promise->fail(result.failure());
  } else {
    promise->set(result.get());
  }

  delete promise;
  post_cleanup_hook();
}

}  // namespace internal {


Try<Subprocess> subprocess(
    const string& path,
    vector<string> argv,
    const Subprocess::IO& in,
    const Subprocess::IO& out,
    const Subprocess::IO& err,
    const Setsid set_sid,
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
    process::internal::close(stdinfds, stdoutfds, stderrfds);
    return Error(output.error());
  }

  stdoutfds = output.get();

  // Prepare the file descriptor(s) for stderr.
  output = err.output();
  if (output.isError()) {
    process::internal::close(stdinfds, stdoutfds, stderrfds);
    return Error(output.error());
  }

  stderrfds = output.get();

#ifndef __WINDOWS__
  // TODO(jieyu): Consider using O_CLOEXEC for atomic close-on-exec.
  Try<Nothing> cloexec = internal::cloexec(stdinfds, stdoutfds, stderrfds);
  if (cloexec.isError()) {
    process::internal::close(stdinfds, stdoutfds, stderrfds);
    return Error("Failed to cloexec: " + cloexec.error());
  }
#endif // __WINDOWS__

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

#ifndef __WINDOWS__
  Try<pid_t> pid =
    internal::clone_child(path, argv, set_sid, environment, _clone,
                          parent_hooks, working_directory, watchdog, stdinfds,
                          stdoutfds, stderrfds);

  if (pid.isError()) {
    return Error(pid.error());
  }
#else
  // Create the child process and pass the stdin/stdout/stderr handles.
  Try<PROCESS_INFORMATION> processInformation = createChildProcess(
      path,
      argv,
      environment,
      stdinfds,
      stdoutfds,
      stderrfds);

  if (processInformation.isError()) {
    process::internal::close(stdinfds, stdoutfds, stderrfds);
    return Error("Could not launch child process" + processInformation.error());
  }

  if (processInformation.get().dwProcessId == -1) {
    // Save the errno as 'close' below might overwrite it.
    ErrnoError error("Failed to clone");
    process::internal::close(stdinfds, stdoutfds, stderrfds);
    return error;
  }

  Try<pid_t> pid = processInformation.get().dwProcessId;
#endif // __WINDOWS__

  // Parent.
  Subprocess process;
#ifdef __WINDOWS__
  process.data->handle = processInformation.get().hProcess;
  process.data->pid = processInformation.get().dwProcessId;
#else
  process.data->pid = pid.get();
#endif // __WINDOWS__

  // Close the child-ends of the file descriptors that are created
  // by this function.
  os::close(stdinfds.read);
  os::close(stdoutfds.write);
  os::close(stderrfds.write);

  // For any pipes, store the parent side of the pipe so that
  // the user can communicate with the subprocess.
  process.data->in = stdinfds.write;
  process.data->out = stdoutfds.read;
  process.data->err = stderrfds.read;

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
  const lambda::function<void()> cleanup_hook =
#ifdef __WINDOWS__
    []() { os::close(processInformation.get().hProcess); };
#else
    []() {};
#endif // __WINDOWS__
  process::reap(pid.get())
    .onAny(
        lambda::bind(
            internal::cleanup,
            lambda::_1,
            promise,
            process,
            cleanup_hook));

#ifdef __WINDOWS__
  ResumeThread(processInformation.get().hThread);
  ::CloseHandle(processInformation.get().hThread);
#endif // __WINDOWS__

  return process;
}

}  // namespace process {
