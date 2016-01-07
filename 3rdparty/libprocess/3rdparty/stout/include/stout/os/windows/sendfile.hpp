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
// descriptor to the output socket. On error, returns -1 and
// errno indicates the error.
// NOTE: The following limitations exist because of the OS X
// implementation of sendfile:
//   1. s must be a stream oriented socket descriptor.
//   2. fd must be a regular file descriptor.

inline ssize_t sendfile(int s, int fd, off_t offset, size_t length)
{
  // NOTE: It is not necessary to close the `HANDLE`; when we call `_close` on
  // `fd` will close the underlying `HANDLE` as well.
  HANDLE file = (HANDLE)_get_osfhandle(fd);
  OVERLAPPED off = {0, 0, {(DWORD)offset, (DWORD)(offset>>32)}, NULL};
  BOOL transmit_initiated = TransmitFile(s, file, length, 0, &off, NULL, 0);

  DWORD sent_bytes = 0;
  DWORD flags = 0;
  BOOL transmit_result = WSAGetOverlappedResult(s, &off, &sent_bytes, TRUE,
                                                &flags);

  if (transmit_initiated && transmit_result) {
    return sent_bytes;
  }

  errno = WSAGetLastError();
  return -1;
}

} // namespace os {

#endif // __STOUT_OS_WINDOWS_SENDFILE_HPP__
