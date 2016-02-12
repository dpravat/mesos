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

#include <stout/lambda.hpp>
#include <stout/windows.hpp>

#include <stdlib.h>

using std::cerr;
using std::endl;

namespace process {

class Winsock {
public:
  // Initializes Winsock and calls `::exit(1)` on failure.
  Winsock() : Winsock(&::exit, EXIT_FAILURE) { }

  // Initializes Winsock and calls the specified function on failure. The intent
  // is to have the caller pass a function that will exit the process with
  // an error code (specified by the `failureCode` argument).
  Winsock(
      const lambda::function<void(int)>& onFailureFunc,
      int failureCode) :
    onFailure(onFailureFunc), initialized(false) {
    if (!initialize()) {
      onFailure(failureCode);
    }
  }

  ~Winsock() {
    cleanup();
  }

private:
  const unsigned int retries = 10;
  bool initialized;
  const lambda::function<void(int)>& onFailure;

  inline bool initialize() {
    if (initialized) {
      cerr << "Already initialized.";
      return true;
    }

    // Initialize WinSock (request version 2.2).
    WORD requestedVersion = MAKEWORD(2, 2);
    WSADATA data;

    const int result = ::WSAStartup(requestedVersion, &data);
    if (result != 0) {
      const int error = ::WSAGetLastError();
      cerr << "Could not initialize WinSock, error code : " << error << endl;
      return false;
    }

    // Check that the WinSock version we got back is 2.2 or higher.
    // The high-order byte specifies the minor version number.
    if (LOBYTE(data.wVersion) < 2 ||
        (LOBYTE(data.wVersion) == 2 && HIBYTE(data.wVersion) != 2)) {
      cerr << "Incorrect WinSock version found : " << LOBYTE(data.wVersion)
        << "." << HIBYTE(data.wVersion) << endl;

      // WinSock was initialized, we just didn't like the version, so we need to
      // clean up.
      if (::WSACleanup() != 0) {
        const int error = ::WSAGetLastError();
        cerr << "Could not cleanup WinSock, error code : " << error << endl;
      }

      return false;
    }

    initialized = true;
    return true;
  }

  inline bool cleanup() {
    if (!initialized) {
      cerr << "Winsock not initialized.";
      return false;
    }

    // Cleanup WinSock. Wait for any outstanding socket operations to complete
    // before exiting. Retry for a maximum of 10 times at 1 second intervals.
    int retriesLeft = retries;

    while (retriesLeft > 0) {
      const int result = ::WSACleanup();
      if (result != 0) {
        const int error = ::WSAGetLastError();
        // Make it idempotent.
        if (error == WSANOTINITIALISED) {
          return false;
        }

        // Wait for any blocking calls to complete and retry after 1 second.
        if (error == WSAEINPROGRESS) {
          cerr << "Waiting for outstanding WinSock calls to complete." << endl;
          ::Sleep(1000);
          retriesLeft--;
        }
        else {
          cerr << "Could not cleanup WinSock, error code : " << error << endl;
          return false;
        }
      }
    }
    if (retriesLeft == 0) {
      return false;
    }

    return true;
  }
};

} // namespace process {

#endif // __PROCESS_WINDOWS_WINSOCK_HPP__
