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

#ifndef __STOUT_OS_POSIX_SIGNALHANDLER_HPP__
#define __STOUT_OS_POSIX_SIGNALHANDLER_HPP__

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <glog/logging.h>
#include <functional>

namespace os {

  typedef std::function<void(int, int)> SignalHandler;
  // Not using extern as this is used only on a single module
  SignalHandler* signaledWrapper = NULL;

  void signalHandler(int sig, siginfo_t* siginfo, void* context)
  {
    if (signaledWrapper != NULL) {
      (*signaledWrapper)(sig, siginfo->si_uid);
    }
  }

  int configureSignal(const std::function<void(int, int)>& signal)
  {
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));

    signaledWrapper = new SignalHandler(signal);

    // Do not block additional signals while in the handler.
    sigemptyset(&action.sa_mask);

    // The SA_SIGINFO flag tells sigaction() to use
    // the sa_sigaction field, not sa_handler.
    action.sa_flags = SA_SIGINFO;

    action.sa_sigaction = signalHandler;

    return sigaction(SIGUSR1, &action, NULL);
    }

} // namespace os {

#endif // __STOUT_OS_POSIX_SIGNALHANDLER_HPP__
