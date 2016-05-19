// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __LAUNCHER_EXECUTOR_HPP__
#define __LAUNCHER_EXECUTOR_HPP__

#include <iostream>

#include <process/pipe.hpp>

#include <stout/option.hpp>
#include <stout/os.hpp>
#include <stout/strings.hpp>

using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::vector;

namespace mesos {
namespace internal {

using namespace process;

inline pid_t launchTaskWindows(
    const TaskInfo& task,
    const CommandInfo& command,
    char** argv,
    Option<char**>& override,
    Option<string>& rootfs)
{
  PROCESS_INFORMATION processInfo;
  ::ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));

  STARTUPINFO startupInfo;
  ::ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
  startupInfo.cb = sizeof(STARTUPINFO);

  string executable;
  string commandLine = task.command().value();

  if (override.isNone()) {
    if (command.shell()) {
      // Use Windows shell (`cmd.exe`). Look for it in the system folder.
      char systemDir[MAX_PATH];
      if (!::GetSystemDirectory(systemDir, MAX_PATH)) {
        // No way to recover from this, safe to exit the process.
        abort();
      }

      executable = path::join(systemDir, os::Shell::name);

      // `cmd.exe` needs to be used in conjunction with the `/c` parameter.
      // For compliance with C-style applications, `cmd.exe` should be passed
      // as `argv[0]`.
      // TODO(alexnaparu): Quotes are probably needed after `/c`.
      commandLine = os::args(
          os::Shell::arg0, os::Shell::arg1, commandLine);
    }
    else {
      // Not a shell command, execute as-is.
      executable = command.value();
      commandLine = os::stringify_args(argv);
    }
  }
  else {
    // Convert all arguments to a single space-separated string.
    commandLine = os::stringify_args(override.get());
  }

  cout << commandLine << endl;

  // There are many wrappers on `CreateProcess` that are more user-friendly,
  // but they don't return the PID of the child process.
  BOOL createProcessResult = ::CreateProcess(
      executable.empty() ? NULL : executable.c_str(), // Module to load.
      (LPSTR)commandLine.c_str(),                     // Command line.
      NULL,                 // Default security attributes.
      NULL,                 // Default primary thread security attributes.
      TRUE,                 // Inherited parent process handles.
      0,                    // Default creation flags.
      NULL,                 // Use parent's environment.
      NULL,                 // Use parent's current directory.
      &startupInfo,         // STARTUPINFO pointer.
      &processInfo);        // PROCESS_INFORMATION pointer.

  if (!createProcessResult) {
    cout << "launchTaskWindows: CreateProcess failed with error code" <<
        GetLastError() << endl;

    abort();
  }

  return processInfo.dwProcessId;
}

} // namespace internal {
} // namespace mesos {

#endif // __LAUNCHER_EXECUTOR_HPP__
