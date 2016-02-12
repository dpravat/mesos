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

#ifndef __PROCESS_POSIX_PIPE_HPP__
#define __PROCESS_POSIX_PIPE_HPP__

#include <unistd.h>

#include <stout/error.hpp>
#include <stout/try.hpp>


namespace process {

// A platform-independent, non-RAII pipe implementation.
class Pipe
{
public:
  const int read;
  const int write;

  ~Pipe()
  {
    // Don't clean up. `Pipe` is not intended to be RAII.
  }

  static Try<Pipe> create()
  {
    int pipefd[2];
    if (::pipe(pipefd) == -1) {
      return ErrnoError("Pipe::create: could not create pipe.");
    }

    return Pipe(pipefd[0], pipefd[1]);
  }

  static Try<Pipe> from_pair(int read_fd, int write_fd)
  {
    return Pipe(read_fd, write_fd);
  }

private:
  Pipe(int readHandle, int writeHandle)
    : read(readHandle), write(writeHandle) { }
};

} // namespace process {

#endif // __PROCESS_POSIX_PIPE_HPP__
