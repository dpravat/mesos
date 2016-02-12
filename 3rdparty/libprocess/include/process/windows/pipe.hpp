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

#include <stout/nothing.hpp>
#include <stout/try.hpp>
#include <stout/windows.hpp>

namespace process {

class Pipe {
private:
  // Platform-specific pipe handles (`HANDLE` values).
  HANDLE _nativeRead;
  HANDLE _nativeWrite;

public:
  Pipe() :
      _nativeRead(INVALID_HANDLE_VALUE),
      _nativeWrite(INVALID_HANDLE_VALUE),
      read(-1),
      write(-1) { }

  // Use existing platform-specific handles instead of creating a pipe. Callers
  // should verify that the `read` and `write` descriptors are valid before
  // using them.
  Pipe(uintptr_t readHandle, uintptr_t writeHandle) :
      _nativeRead((HANDLE)readHandle), _nativeWrite((HANDLE)writeHandle) {
    read = ::_open_osfhandle((intptr_t)_nativeRead, _O_RDONLY | _O_TEXT);
    write = ::_open_osfhandle((intptr_t)_nativeWrite, _O_APPEND | _O_TEXT);
  }

  ~Pipe() {
    // Do not cleanup pipe handles on destruction, this is the responsibility
    // of the caller.
  }

  inline Try<Nothing> Create() {
    // Create inheritable pipe, as described in MSDN[1]
    //
    // [1] https://msdn.microsoft.com/en-us/library/windows/desktop/aa365782(v=vs.85).aspx
    SECURITY_ATTRIBUTES securityAttr;
    securityAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    securityAttr.bInheritHandle = TRUE;
    securityAttr.lpSecurityDescriptor = NULL;

    BOOL result = ::CreatePipe(
        &_nativeRead,
        &_nativeWrite,
        &securityAttr,
        0);

    if (!result) {
      return WindowsError("Pipe::Create: could not create pipe.");
    }

    // Open POSIX-style file descriptors for both pipe handles.
    read = ::_open_osfhandle((intptr_t)_nativeRead, _O_RDONLY | _O_TEXT);
    if (read < 0) {
      return WindowsError("Pipe::Create: could not open file descriptor for "
          "read handle.");
    }

    write = ::_open_osfhandle((intptr_t)_nativeWrite, _O_APPEND | _O_TEXT);
    if (write < 0) {
      return WindowsError("Pipe::Create: could not open file descriptor for "
          "write handle.");
    }

    return Nothing();
  }

  inline uintptr_t nativeRead() {
    // Safe to cast this, since `uintptr_t` is guaranteed to hold a pointer.
    return (uintptr_t)_nativeRead;
  }

  inline uintptr_t nativeWrite() {
    return (uintptr_t)_nativeWrite;
  }

  // POSIX-compliant pipe descriptors (unsafe to use outside the process).
  int read;
  int write;
};

} // namespace process {

#endif // __PROCESS_WINDOWS_PIPE_HPP__
