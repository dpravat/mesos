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

#ifndef __STOUT_OS_WINDOWS_SHELL_HPP__
#define __STOUT_OS_WINDOWS_SHELL_HPP__

#include <stdarg.h> // For va_list, va_start, etc.

#include <process.h>

#include <ostream>
#include <string>

#include <stout/try.hpp>

// os::sytem returns -1 if the processor cannot be started
// therefore any return valu indicates the process has been started
#define WIFEXITED(x) ((x) != -1)
#define WEXITSTATUS(x) (x)

namespace os {

// Runs a shell command formatted with varargs and return the return value
// of the command. Optionally, the output is returned via an argument.
// TODO(vinod): Pass an istream object that can provide input to the command.
template <typename... T>
Try<std::string> shell(const std::string& fmt, const T&... t)
{
  UNIMPLEMENTED;
}

struct shell_const
{
static const char* name()
{
  return "cmd.exe";
}
static const char* arg0()
{
  return "cmd.exe";
}
static const char* arg1()
{
  return "/c";
}
};

template <typename... T>
int execlp(const char* path, const T*... t)
{
  return ::execlp(path, t...);
}

inline int execvp(const char *file, char *const argv[])
{
    return _execvp(file, argv);
}

// Executes a command by calling "cmd /c <command>", and returns
// after the command has been completed. Returns 0 if succeeds, and
// return -1 on error
inline int system(const std::string& command)
{
    return ::_spawnl(_P_WAIT, shell_const::name(), shell_const::arg0(),
                      shell_const::arg1(), command.c_str());
}

} // namespace os {

#endif // __STOUT_OS_WINDOWS_SHELL_HPP__
