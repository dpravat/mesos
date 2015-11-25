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
// limitations under the License.tions under the License.

#ifndef __STOUT_WINDOWS_FS_HPP__
#define __STOUT_WINDOWS_FS_HPP__

#include <string>

#include <stout/bytes.hpp>
#include <stout/error.hpp>
#include <stout/nothing.hpp>
#include <stout/try.hpp>

#include <stout/internal/windows/symlink.hpp>

namespace fs {

// Returns the total disk size in bytes.
inline Try<Bytes> size(const std::string& path = "/")
{
  Result<std::string> realPath = os::realpath(path);

  if (realPath.isError()) {
    return Error(realPath.error());
  }

  ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
  if (!GetDiskFreeSpaceEx(realPath.get().c_str(), &freeBytesAvailable,
                          &totalNumberOfBytes, &totalNumberOfFreeBytes))
  {
    return WindowsError("Error invoking GetDiskFreeSpaceEx on '" + path + "'");
  }

  return Bytes(totalNumberOfBytes.QuadPart);
}


// Returns relative disk usage of the file system that the given path
// is mounted at.
inline Try<double> usage(const std::string& path = "/")
{
  Result<std::string> realPath = os::realpath(path);

  if (realPath.isError()) {
    return Error(realPath.error());
  }

  ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
  if (!GetDiskFreeSpaceEx(realPath.get().c_str(), &freeBytesAvailable,
        &totalNumberOfBytes, &totalNumberOfFreeBytes))
  {
    return WindowsError("Error invoking GetDiskFreeSpaceEx on '" + path + "'");
  }

  return ((double)(totalNumberOfBytes.QuadPart -
    totalNumberOfFreeBytes.QuadPart)) / ((double)totalNumberOfBytes.QuadPart);
}


inline Try<Nothing> symlink(
    const std::string& original,
    const std::string& link)
{
  return internal::windows::createReparsePoint(link, original);
}

} // namespace fs {

#endif // __STOUT_WINDOWS_FS_HPP__
