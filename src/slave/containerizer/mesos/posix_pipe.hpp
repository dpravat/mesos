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

#ifndef __MESOS_CONTAINERIZER_POSIX_PIPE_HPP__
#define __MESOS_CONTAINERIZER_POSIX_PIPE_HPP__

#include <unistd.h>

#include <stout/error.hpp>
#include <stout/try.hpp>


namespace mesos {
namespace internal {

inline std::array<int, 2> create_local_pipe() {
  int pipefd[2];
  if (::pipe(pipefd) < 0 ) {
    perror("Failed to create pipe");
    abort();
  };
  return {{pipefd[0], pipefd[1]}};
}

inline std::array<int, 2> global_from_local(std::array<int, 2> in)
{
    return in;
}

inline std::array<int, 2> local_from_global(std::array<int, 2> in)
{
    return in;
}

} // namespace internal {
} // namespace mesos {

#endif // __MESOS_CONTAINERIZER_POSIX_PIPE_HPP__
