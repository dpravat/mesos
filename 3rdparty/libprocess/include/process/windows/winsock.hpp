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
#ifndef __PROCESS_WINDOWS_WINSOCK_HPP__
#define __PROCESS_WINDOWS_WINSOCK_HPP__

#include <stdlib.h>

#include <glog/logging.h>

#include <stout/abort.hpp>
#include <stout/lambda.hpp>
#include <stout/windows.hpp>

#include <stout/os/socket.hpp>


namespace process {

class Winsock {
public:
  // Initializes Winsock and calls `::exit(1)` on failure.
  Winsock() : Winsock(&::exit, EXIT_FAILURE) { }

  // Initializes Winsock and calls the specified function on failure. The intent
  // is to have the caller pass a function that will exit the process with
  // an error code (specified by the `failureCode` argument).
  Winsock(
      const lambda::function<void(int)>& on_failure_callback,
      int failureCode) : on_failure(on_failure_callback), initialized(false) {
    if (!initialize()) {
      on_failure(failureCode);
    }
  }

  ~Winsock() {
    cleanup();
  }

private:
  const unsigned int retries = 10;
  bool initialized;
  const lambda::function<void(int)>& on_failure;

  // Attempts to initialize WSA stack. Returns `true` if we succeeded, or if
  // the `initialized` variable is already `true`. Returns false if there was a
  // failure while trying ot initialize the stack.
  inline bool initialize() {
    if (initialized) {
      LOG(WARNING) << "Attempted to call `WSAStartup`, but WinSock has already "
                      "been initialized";
      return true;
    }

    if (net::wsa_initialize()) {
      initialized = true;
      return true;
    } else {
      return false;
    }
  }

  // Attempts to tear down the WSA stack. Returns `true` if we succeeded, or
  // if the `initialized` variable has not been set. Returns `false` if we
  // failed to tear down the stack.
  inline bool cleanup() {
    if (!initialized) {
      LOG(WARNING) << "Attempted to call `WSACleanup`, but WinSock stack has "
                      "not been not initialized";
      return true;
    }

    return net::wsa_cleanup();
  }
};

} // namespace process {

#endif // __PROCESS_WINDOWS_WINSOCK_HPP__
