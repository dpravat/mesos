// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License

#ifndef __MESOS_CONTAINERIZER_WINDOWS_PIPE_HPP__
#define __MESOS_CONTAINERIZER_WINDOWS_PIPE_HPP__

#include <stout/try.hpp>
#include <stout/windows.hpp>


namespace mesos {
namespace internal {

inline std::array<int, 2> create_local_pipe() {
    // Create inheritable pipe, as described in MSDN[1].
    //
    // [1] https://msdn.microsoft.com/en-us/library/windows/desktop/aa365782(v=vs.85).aspx
    SECURITY_ATTRIBUTES securityAttr;
    securityAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    securityAttr.bInheritHandle = TRUE;
    securityAttr.lpSecurityDescriptor = NULL;

    HANDLE read_handle;
    HANDLE write_handle;

    const BOOL result = ::CreatePipe(&read_handle, &write_handle,
                                     &securityAttr, 0);

    return {{ _open_osfhandle(
        reinterpret_cast<intptr_t>(read_handle),
        _O_RDONLY | _O_TEXT),
      _open_osfhandle(
        reinterpret_cast<intptr_t>(write_handle),
        _O_TEXT) }};
}

inline std::array<intptr_t, 2> global_from_local(std::array<int, 2> in)
{
  return {{ ::_get_osfhandle(in[0]), ::_get_osfhandle(in[1]) }};
}

inline std::array<int, 2> local_from_global(std::array<intptr_t, 2> in)
{
  return {{ ::_open_osfhandle(in[0],  _O_RDONLY | _O_TEXT),
    ::_open_osfhandle(in[1], _O_TEXT) }};
}

} // namespace internal {
} // namespace mesos {

#endif // __MESOS_CONTAINERIZER_WINDOWS_PIPE_HPP__
