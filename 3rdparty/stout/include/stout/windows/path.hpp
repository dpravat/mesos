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

#ifndef __STOUT_WINDOWS_PATH_HPP__
#define __STOUT_WINDOWS_PATH_HPP__

#include <stout/windows.hpp>


namespace path {

inline std::string temp_path()
{
  // Get temp folder for current user.
  char temp_folder[MAX_PATH + 1];
  if (::GetTempPath(MAX_PATH + 1, temp_folder) == 0) {
    // Failed, try current folder.
    if (::GetCurrentDirectory(MAX_PATH + 1, temp_folder) == 0) {
      // Failed, use relative path.
      return ".";
    }
  }

  return std::string(temp_folder);
}

} // namespace path {

#endif // __STOUT_WINDOWS_PATH_HPP__
