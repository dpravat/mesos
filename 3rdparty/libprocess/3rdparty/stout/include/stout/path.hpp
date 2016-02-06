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

#ifndef __STOUT_PATH_HPP__
#define __STOUT_PATH_HPP__

#include <string>
#include <utility>
#include <vector>

#ifdef __WINDOWS__
#define PATH_SEPARATOR_CHAR '\\'
#define PATH_SEPARATOR_STRING "\\"
#else
#define PATH_SEPARATOR_CHAR '/'
#define PATH_SEPARATOR_STRING "/"
#endif // __WINDOWS__

#include <stout/strings.hpp>

namespace path {

// Base case.
inline std::string join(const std::string& path1, const std::string& path2)
{
  return strings::remove(path1, PATH_SEPARATOR_STRING, strings::SUFFIX) +
      PATH_SEPARATOR_STRING +
      strings::remove(path2, PATH_SEPARATOR_STRING, strings::PREFIX);
}


template <typename... Paths>
inline std::string join(
    const std::string& path1,
    const std::string& path2,
    Paths&&... paths)
{
  return join(path1, join(path2, std::forward<Paths>(paths)...));
}


inline std::string join(const std::vector<std::string>& paths)
{
  if (paths.empty()) {
    return "";
  }

  std::string result = paths[0];
  for (size_t i = 1; i < paths.size(); ++i) {
    result = join(result, paths[i]);
  }
  return result;
}


inline bool absolute(const std::string& path)
{
  if (path.empty() || path[0] != PATH_SEPARATOR_CHAR) {
    return false;
  }

  return true;
}

} // namespace path {


/**
 * Represents a POSIX or Windows file system path and offers common path
 * manipulations.
 * When reading the comments below, keep in mind that '/' refers to the path
 * separator character, so read it as "'/' or '\', depending on platform". For
 * obvious reasons, this was not spelled out every time.
 */
class Path
{
public:
  explicit Path(const std::string& path)
    : value(strings::remove(path, "file://", strings::PREFIX)) {}

  // TODO(cmaloney): Add more useful operations such as 'directoryname()',
  // 'filename()', etc.

  /**
   * Extracts the component following the final '/'. Trailing '/'
   * characters are not counted as part of the pathname.
   *
   * Like the standard '::basename()' except it is thread safe.
   *
   * The following list of examples (taken from SUSv2) shows the
   * strings returned by basename() for different paths:
   *
   * path        | basename
   * ----------- | -----------
   * "/usr/lib"  | "lib"
   * "/usr/"     | "usr"
   * "usr"       | "usr"
   * "/"         | "/"
   * "."         | "."
   * ".."        | ".."
   *
   * @return The component following the final '/'. If Path does not
   *   contain a '/', this returns a copy of Path. If Path is the
   *   string "/", then this returns the string "/". If Path is an
   *   empty string, then it returns the string ".".
   */
  inline std::string basename() const
  {
    if (value.empty()) {
      return std::string(".");
    }

    size_t end = value.size() - 1;

    // Remove trailing slashes.
    if (value[end] == PATH_SEPARATOR_CHAR) {
      end = value.find_last_not_of(PATH_SEPARATOR_CHAR, end);

      // Paths containing only slashes result into "/".
      if (end == std::string::npos) {
        return std::string(PATH_SEPARATOR_STRING);
      }
    }

    // 'start' should point towards the character after the last slash
    // that is non trailing.
    size_t start = value.find_last_of(PATH_SEPARATOR_CHAR, end);

    if (start == std::string::npos) {
      start = 0;
    } else {
      start++;
    }

    return value.substr(start, end + 1 - start);
  }

  // TODO(anaparu) Make sure this works on Windows for very short path names,
  // such as "C:\Temp". There is a distinction between "C:" and "C:\", the
  // former means "current directory of the C drive", while the latter means
  // "The root of the C drive". Also make sure that UNC paths are handled.
  // Will probably need to use the Windows path functions for that.
  /**
   * Extracts the component up to, but not including, the final '/'.
   * Trailing '/' characters are not counted as part of the pathname.
   *
   * Like the standard '::dirname()' except it is thread safe.
   *
   * The following list of examples (taken from SUSv2) shows the
   * strings returned by dirname() for different paths:
   *
   * path        | dirname
   * ----------- | -----------
   * "/usr/lib"  | "/usr"
   * "/usr/"     | "/"
   * "usr"       | "."
   * "/"         | "/"
   * "."         | "."
   * ".."        | "."
   *
   * @return The component up to, but not including, the final '/'. If
   *   Path does not contain a '/', then this returns the string ".".
   *   If Path is the string "/", then this returns the string "/".
   *   If Path is an empty string, then this returns the string ".".
   */
  inline std::string dirname() const
  {
    if (value.empty()) {
      return std::string(".");
    }

    size_t end = value.size() - 1;

    // Remove trailing slashes.
    if (value[end] == PATH_SEPARATOR_CHAR) {
      end = value.find_last_not_of(PATH_SEPARATOR_CHAR, end);
    }

    // Remove anything trailing the last slash.
    end = value.find_last_of(PATH_SEPARATOR_CHAR, end);

    // Paths containing no slashes result in ".".
    if (end == std::string::npos) {
      return std::string(".");
    }

    // Paths containing only slashes result in "/".
    if (end == 0) {
      return std::string(PATH_SEPARATOR_STRING);
    }

    // 'end' should point towards the last non slash character
    // preceding the last slash.
    end = value.find_last_not_of(PATH_SEPARATOR_CHAR, end);

    // Paths containing no non slash characters result in "/".
    if (end == std::string::npos) {
      return std::string(PATH_SEPARATOR_STRING);
    }

    return value.substr(0, end + 1);
  }

  /**
   * Returns the file extension of the path, including the dot.
   *
   * Returns None if the basename contains no dots, or consists
   * entirely of dots (i.e. '.', '..').
   *
   * Examples:
   *
   *   path         | extension
   *   ----------   | -----------
   *   "a.txt"      |  ".txt"
   *   "a.tar.gz"   |  ".gz"
   *   ".bashrc"    |  ".bashrc"
   *   "a"          |  None
   *   "."          |  None
   *   ".."         |  None
   */
  inline Option<std::string> extension() const
  {
    std::string _basename = basename();
    size_t index = _basename.rfind(".");

    if (_basename == "." || _basename == ".." || index == std::string::npos) {
      return None();
    }

    return _basename.substr(index);
  }

  // Checks whether the path is absolute.
  inline bool absolute() const
  {
    return path::absolute(value);
  }

  // Implicit conversion from Path to string.
  operator std::string() const
  {
    return value;
  }

  const std::string value;
};


inline std::ostream& operator<<(
    std::ostream& stream,
    const Path& path)
{
  return stream << path.value;
}

#endif // __STOUT_PATH_HPP__
