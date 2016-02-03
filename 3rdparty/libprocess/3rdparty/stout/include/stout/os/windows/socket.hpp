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

#ifndef __STOUT_OS_WINDOWS_SOCKET_HPP__
#define __STOUT_OS_WINDOWS_SOCKET_HPP__

#include <stout/nothing.hpp>
#include <stout/try.hpp>

#include <stout/os/socket.hpp>

namespace net {

/**
 * Returns a socket file descriptor for the specified options.
 *
 * **NOTE:** on OS X, the returned socket will have the SO_NOSIGPIPE
 * option set.
 */
inline Try<int> socket(int family, int type, int protocol)
{
  int s;
  if ((s = ::socket(family, type, protocol)) == INVALID_SOCKET) {
    return ErrnoError();
  }

  return s;
}

inline bool isSocket(int fd)
{

  // We use an 'int' but expect a SOCKET if this is Windows.
  static_assert(sizeof(SOCKET) == sizeof(int), "Can not use int for SOCKET");

  int value = 0;
  int length = sizeof(int);

  if (::getsockopt(
          fd,
          SOL_SOCKET,
          SO_TYPE,
          (char*) &value,
          &length) == SOCKET_ERROR) {
    switch (WSAGetLastError()) {
      case WSAENOTSOCK:
        return false;
      default:
        // TODO(benh): Handle `WSANOTINITIALISED`
        ABORT("Not expecting 'getsockopt' to fail when passed a valid socket");
    }
  }

  return true;
}

} // namespace net {

#endif // __STOUT_OS_WINDOWS_SOCKET_HPP__