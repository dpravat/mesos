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
#include <stout/windows.hpp>

using std::array;
using std::string;

namespace process {

using InputFileDescriptors = Subprocess::IO::InputFileDescriptors;
using OutputFileDescriptors = Subprocess::IO::OutputFileDescriptors;

namespace internal {

// TODO(hausdorff): Rethink name here, write a comment about this function.
static Try<HANDLE> createIoPath(const string& path, DWORD accessFlags)
{
  // The `TRUE` in the last field makes this duplicate handle inheritable.
  SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
  HANDLE handle = ::CreateFile(
      path.c_str(),
      accessFlags,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      &sa,
      CREATE_NEW,
      FILE_ATTRIBUTE_NORMAL,
      nullptr);

  if (handle == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_EXISTS) {
    handle = ::CreateFile(
      path.c_str(),
      accessFlags,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      &sa,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      nullptr);
  }

  if (handle == INVALID_HANDLE_VALUE) {
    return WindowsError("Failed to open '" + path + "'");
  }

  return handle;
}


static Try<HANDLE> createInputFile(const string& path)
{
  // Get a handle to the `stdin` file. Use `GENERIC_READ` and
  // `FILE_SHARE_READ` to make the handle read-only (as `stdin` should
  // be), but allow others to read from the same file.
  return createIoPath(path, GENERIC_READ);
}


static Try<HANDLE> createOutputFile(const string& path)
{
  // Get a handle to the `stdout` file. Use `GENERIC_WRITE` to make the
  // handle writeable (as `stdout` should be), but still allow other processes
  // to read from the file.
  return createIoPath(path, GENERIC_WRITE);
}


}  // namespace internal {


Subprocess::IO Subprocess::PIPE()
{
  return Subprocess::IO(
      []() -> Try<InputFileDescriptors> {
        int_fd handles[2];
        Try<Nothing> res = os::pipe(handles, os::SOCKETMODE::WRITE);
        if (res.isError()) {
          return Error(res.error());
        }

        InputFileDescriptors fds;
        fds.read = handles[0];
        fds.write = handles[1];
        return fds;
      },
      []() -> Try<OutputFileDescriptors> {
        int_fd handles[2];
        Try<Nothing> res = os::pipe(handles, os::SOCKETMODE::READ);
        if (res.isError()) {
          return Error(res.error());
        }
        OutputFileDescriptors fds;
        fds.read = handles[0];
        fds.write = handles[1];
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


Subprocess::IO Subprocess::FD(const int_fd& fd, IO::FDType type)
{
  return Subprocess::IO(
      [fd, type]() -> Try<InputFileDescriptors> {
        int_fd new_fd;
        switch (type) {
          case Subprocess::IO::DUPLICATED: {
            new_fd = os::dup(fd);
            if (new_fd == -1) {
              return WindowsError(" to duplicate handle");
            }
            break;
          }
          case Subprocess::IO::OWNED:
            new_fd = fd;
            break;
        }
        InputFileDescriptors fds;
        fds.read = new_fd;
        return fds;
      },
      [fd, type]() -> Try<OutputFileDescriptors> {
        int_fd new_fd;
        switch (type) {
          case Subprocess::IO::DUPLICATED: {
            new_fd = os::dup(fd);
            if (new_fd == -1) {
              return WindowsError("Failed to duplicate handle");
            }
            break;
          }
          case Subprocess::IO::OWNED:
            new_fd = fd;
            break;
        }

        OutputFileDescriptors fds;
        fds.write = new_fd;
        return fds;
      });
}

}  // namespace process {
