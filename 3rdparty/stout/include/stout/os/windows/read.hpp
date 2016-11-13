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

#include <stout/result.hpp>
#include <stout/windows.hpp> // For order-dependent networking headers.

#include <stout/os/socket.hpp>


namespace os {

// Forward declaration for an OS-agnostic `read`.
inline Result<std::string> read(const FileDesc& fd, size_t size);


inline ssize_t read(const FileDesc& fd, void* data, size_t size)
{
  CHECK_LE(size, UINT_MAX);

  if (fd.isSocket()) {
    return ::recv(fd, (char*) data, static_cast<unsigned int>(size), 0);
  }
  return ::_read(fd.operator int(), data, static_cast<unsigned int>(size));
}


inline long lseek(const FileDesc& fd, long offset, int origin) {
  return _lseek(fd.operator int(), offset, origin);
}

} // namespace os {

#endif // __STOUT_OS_WINDOWS_READ_HPP__
