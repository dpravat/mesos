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

#ifndef __PROCESS_WINDOWS_PIPE_HPP__
#define __PROCESS_WINDOWS_PIPE_HPP__

#include <stout/try.hpp>
#include <stout/windows.hpp>


namespace process {

// A platform-independent, non-RAII pipe implementation.
class Pipe
{
public:
  const int read;
  const int write;

  ~Pipe()
  {
    // Don't clean up. `Pipe` is not intended to be RAII.
  }

  static Try<Pipe> create()
  {
    // Create inheritable pipe, as described in MSDN[1].
    //
    // [1] https://msdn.microsoft.com/en-us/library/windows/desktop/aa365782(v=vs.85).aspx
    SECURITY_ATTRIBUTES securityAttr;
    securityAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    securityAttr.bInheritHandle = TRUE;
    securityAttr.lpSecurityDescriptor = NULL;

    HANDLE read_handle;
    HANDLE write_handle;

    const BOOL result = ::CreatePipe(&read_handle, &write_handle,
                                     &securityAttr, 0);

    const int read_fd = handle_to_fd(read_handle, _O_RDONLY | _O_TEXT);
    const int write_fd = handle_to_fd(write_handle, _O_RDONLY | _O_TEXT);

    if (!result) {
      return WindowsError("Pipe::Create: could not create pipe.");
    }

    return Pipe(read_fd, write_fd);
  }

  static Try<Pipe> from_pair(int read_fd, int write_fd)
  {
    return Pipe(read_fd, write_fd);
  }

  static Try<Pipe> from_pair(HANDLE read_handle, HANDLE write_handle)
  {
    const int read_fd = handle_to_fd(read_handle, _O_RDONLY | _O_TEXT);
    const int write_fd = handle_to_fd(write_handle, _O_RDONLY | _O_TEXT);

    if (read_fd == -1 || write_fd == -1) {
      return WindowsError("Pipe::from_pair: Failed ot obtain file descriptors "
                          "for one or more of the `HANDLE`s passed in "
                          "as argument");
    }

    return Pipe(read_fd, write_fd);
  }

private:
  Pipe(int read_fd, int write_fd)
    : read(read_fd),
      write(write_fd) { }

  static int handle_to_fd(HANDLE handle, int flags)
  {
    return ::_open_osfhandle(
        reinterpret_cast<intptr_t>(handle),
        flags);
  }
};

} // namespace process {

#endif // __PROCESS_WINDOWS_PIPE_HPP__
