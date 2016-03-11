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

#ifndef __STOUT_OS_WINDOWS_READ_HPP__
#define __STOUT_OS_WINDOWS_READ_HPP__

#include <io.h>

#include <stout/windows.hpp> // For order-dependent networking headers.

#include <stout/os/socket.hpp>


namespace os {
namespace internal {

inline bool read_interrupted()
{
  return WSAGetLastError() == WSAEWOULDBLOCK;
}

} // namespace internal {


inline ssize_t read(int fd, void* data, size_t size)
{
  // TODO(benh): Map any Windows specific return code semantics from
  // either `recv` or `_read` into POSIX semantics (i.e., what the
  // callee will be checking for).
  if (net::isSocket(fd)) {
    return ::recv(fd, (char*)data, size, 0);
  }

  return ::_read(fd, data, size);
}

} // namespace os {

#endif // __STOUT_OS_WINDOWS_READ_HPP__
