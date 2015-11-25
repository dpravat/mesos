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


// Returns a list of all files matching the given pattern. This is meant to
// be a lightweight alternative to glob() - the only supported wildcards are
// `?` and `*`, and only when they appear at the tail end of `pattern` (e.g.
// `/root/dir/subdir/*.txt` or `/root/dir/subdir/file?.txt`
inline Try<std::list<std::string>> list(const std::string& pattern)
{
  WIN32_FIND_DATA findData;
  const HANDLE searchHandle = FindFirstFile(pattern.c_str(), &findData);

  if (searchHandle == INVALID_HANDLE_VALUE) {
    return WindowsError(
      "`fs::list` failed when searching for files with pattern '" +
      pattern + "'");
  }

  std::list<std::string> foundFiles;

  do {
    std::string currentFile(findData.cFileName);

    // Ignore `.` and `..` entries
    if (currentFile.compare(".") != 0 && currentFile.compare("..") != 0)
    {
      foundFiles.push_back(currentFile);
    }
  } while (FindNextFile(searchHandle, &findData));

  // Cache FindNextFile error, FindClose will overwrite it
  DWORD error = ::GetLastError();
  FindClose(searchHandle);

  if (error != ERROR_NO_MORE_FILES)
  {
    ::SetLastError(error);
    return WindowsError(
      "`fs::list`: FindNextFile failed when searching for files with \
      'pattern '" + pattern + "'");
  }

  return foundFiles;
}

} // namespace fs {

#endif // __STOUT_WINDOWS_FS_HPP__
