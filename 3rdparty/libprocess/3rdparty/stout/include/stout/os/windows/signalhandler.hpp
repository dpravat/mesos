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

#ifndef __STOUT_OS_WINDOWS_SIGNALHANDLER_HPP__
#define __STOUT_OS_WINDOWS_SIGNALHANDLER_HPP__

#include <errno.h>
#include <signal.h>
#include <string.h>


#include <errno.h>
#include <signal.h>
#include <string.h>
#include <glog/logging.h>
#include <functional>

namespace os {
  // Not using extern as this is used only on executables
  typedef std::function<void(int, int)> SignalHandler;
  SignalHandler* signaledWrapper = NULL;
  #define SIGUSR1 100
  BOOL CtrlHandler(DWORD fdwCtrlType)
  {
    switch (fdwCtrlType)
    {
    // Handle the CTRL-C signal.
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
      if (signaledWrapper != NULL) {
        (*signaledWrapper)(SIGUSR1, 0);
        return TRUE;
      }
    default:
	  return FALSE;
    }
  }

  int configureSignal(const std::function<void(int, int)>& signal)
  {
    signaledWrapper = new SignalHandler(signal);
    if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE)){
      return 0;
    }
    else {
      return -1;
    }
  }

} // namespace os {

#endif // __STOUT_OS_WINDOWS_SIGNALHANDLER_HPP__
