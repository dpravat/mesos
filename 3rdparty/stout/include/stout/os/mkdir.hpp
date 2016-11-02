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

#ifndef __STOUT_OS_MKDIR_HPP__
#define __STOUT_OS_MKDIR_HPP__

#ifndef __WINDOWS__
#include <sys/stat.h>
#endif // __WINDOWS__

#include <stack>
#include <string>
#include <vector>

#include <stout/error.hpp>
#include <stout/nothing.hpp>
#include <stout/strings.hpp>
#include <stout/try.hpp>

#include <stout/os/constants.hpp>

#ifdef __WINDOWS__
#include <stout/windows.hpp> // To be certain we're using the right `mkdir`.
#endif // __WINDOWS__


namespace os {

inline Try<Nothing> mkdir(const std::string& directory, bool recursive = true)
{
  if (!recursive) {
    if (::mkdir(directory.c_str(), 0755) < 0) {
      return ErrnoError();
    }
  } else {
    std::string last_path = directory;
    std::stack<std::string> stack;
    for(;;) {
      if (::mkdir(last_path.c_str(), 0755) < 0 && errno != EEXIST) {
        stack.push(last_path);
      }
      else {
        break;
      }

      std::string::size_type last_separator = last_path.find_last_of(stringify(os::PATH_SEPARATOR));
      if (last_separator == std::string::npos) {
        break;
      }
      else {
        last_path = last_path.substr(0, last_separator);
      }
    }
    while (stack.size() > 0) {
      std::string path = stack.top();
      if (::mkdir(path.c_str(), 0755) < 0 && errno != EEXIST) {
        return ErrnoError();
      }
      stack.pop();
    }
  }

  return Nothing();
}

} // namespace os {

#endif // __STOUT_OS_MKDIR_HPP__
