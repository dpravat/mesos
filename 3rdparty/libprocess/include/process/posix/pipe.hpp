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

#include <stout/error.hpp>
#include <stout/nothing.hpp>
#include <stout/try.hpp>

#include <unistd.h>

namespace process {

class Pipe {
public:
  Pipe() : read(-1), write(-1) { }

  Pipe(int readHandle, int writeHandle) : read(readHandle), write(writeHandle) {
  }

  inline Try<Nothing> Create() {
    if (::pipe(&read, &write) == -1) {
      return ErrnoError("Pipe::Create: could not create pipe.");
    }
    return Nothing();
  }

  inline int nativeRead() {
    return read;
  }

  inline int nativeWrite() {
    return write;
  }

  int read;
  int write;
}

} // namespace process {

#endif // __PROCESS_POSIX_PIPE_HPP__
