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

#ifndef __STOUT_OS_WINDOWS_SENDFILE_HPP__
#define __STOUT_OS_WINDOWS_SENDFILE_HPP__

#include <errno.h>
#include <stout/windows.hpp>

namespace os {

// Returns the amount of bytes written from the input file
// descriptor to the output socket.
// On error, Try<ssize_t, WindowsSocketError> contains the error.
inline Try<ssize_t, SocketError> sendfile(int s, int fd, off_t offset,
                                          size_t length) {
  // NOTE: It is not necessary to close the `HANDLE`; when we call `_close` on
  // `fd` will close the underlying `HANDLE` as well.
  HANDLE file = (HANDLE)_get_osfhandle(fd);

  LONG hight_Part = (LONG)(offset >> 32);
  if (SetFilePointer(file, (DWORD)offset, &hight_Part, FILE_BEGIN) ==
      INVALID_SET_FILE_POINTER) {
    return WindowsSocketError();
  }

  if (TransmitFile(s, file, length, 0, NULL, NULL, 0) == TRUE) {
    return length;
  } else {
    return WindowsSocketError();
  }
}

} // namespace os {

#endif // __STOUT_OS_WINDOWS_SENDFILE_HPP__
