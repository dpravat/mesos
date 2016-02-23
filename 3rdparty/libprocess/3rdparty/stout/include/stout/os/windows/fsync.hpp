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

#ifndef __STOUT_OS_WINDOWS_FSYNC_HPP__
#define __STOUT_OS_WINDOWS_FSYNC_HPP__

#include <io.h>
#include <errno.h>

#include <stout/error.hpp>
#include <stout/windows.hpp>

#define FSYNC_PASS 0
#define FSYNC_FAIL -1

namespace os {

inline int fsync(int fd)
{
  HANDLE inhandle = (HANDLE)_get_osfhandle(fd);
  if (inhandle == INVALID_HANDLE_VALUE) {
    errno = EBADF;
    return FSYNC_FAIL;
  }

  bool result = FlushFileBuffers(inhandle);
  if (!result) {
    DWORD lasterror = GetLastError();
    if (lasterror == ERROR_INVALID_HANDLE) {
      errno = EINVAL;
    }
    else {
      errno = EIO;
    }
    return FSYNC_FAIL;
  }

  return FSYNC_PASS;
}

} // namespace os {


#endif // __STOUT_OS_WINDOWS_FSYNC_HPP__
