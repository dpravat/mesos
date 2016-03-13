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

#include <process.h>
#include <stdarg.h> // For va_list, va_start, etc.

#include <ostream>
#include <string>

#include <stout/try.hpp>

using std::string;

namespace os {

namespace Shell {

  // Canonical constants used as platform-dependent args to `exec` calls.
  // `name` is the command name, `arg0` is the first argument received
  // by the callee, usually the command name and `arg1` is the second
  // command argument received by the callee.

  constexpr const char* name = "cmd.exe";
  constexpr const char* arg0 = "cmd";
  constexpr const char* arg1 = "/c";
} // namespace Shell {

// Runs a shell command formatted with varargs and return the return value
// of the command. Optionally, the output is returned via an argument.
// TODO(vinod): Pass an istream object that can provide input to the command.
template <typename... T>
Try<std::string> shell(const std::string& fmt, const T... t) = delete;

// Executes a command by calling "cmd /c <command>", and returns
// after the command has been completed. Returns 0 if succeeds, and
// return -1 on error
inline int system(const std::string& command)
{
  return ::_spawnlp(
      _P_WAIT, Shell::name, Shell::arg0, Shell::arg1, command.c_str(), NULL);
}

template<typename... T>
inline int execlp(const char* file, T... t)
{
  exit(::_spawnlp(_P_WAIT, file, t...));
}

// Base case. Concatenates two command-line arguments without escaping the
// values.
inline std::string args(const std::string& arg1, const std::string& arg2)
{
  return arg1 + " " + arg2;
}

// Concatenates multiple command-line arguments without escaping the values.
template <typename... Arguments>
inline std::string args(
  const std::string& arg1, const std::string& arg2, Arguments&&... _args)
{
  return args(arg1, args(arg2, std::forward<Arguments>(_args)...));
}

// Adds double quotes around arguments that contain special characters (like
// spaces and tabls). Also escapes any existing double quotes and backslashes.
inline std::string escape_arg(const std::string& arg)
{
  // A good explanation of how this function works, as well as the original
  // version of this code can be found here[1].
  //
  // [1] http://blogs.msdn.com/b/twistylittlepassagesallalike/archive/2011/04/23/everyone-quotes-arguments-the-wrong-way.aspx
  std::string escaped = "";

  // Only use quotes if needed.
  if (!arg.empty() && arg.find_first_of(" \t\n\v\"") == arg.npos)
  {
    escaped.append(arg);
  } else {
    escaped.push_back('"');
    for (auto iterator = arg.begin(); ; ++iterator) {
      unsigned backslashes = 0;

      while (iterator != arg.end() && *iterator == '\\') {
        ++iterator;
        ++backslashes;
      }

      if (iterator == arg.end()) {
        // Escape all backslashes, but let the terminating
        // double quotation mark we add below be interpreted
        // as a metacharacter.
        escaped.append(backslashes * 2, '\\');
        break;
      }
      else if (*iterator == '"') {
        // Escape all backslashes and the following
        // double quotation mark.
        escaped.append(backslashes * 2 + 1, '\\');
        escaped.push_back(*iterator);
      } else {
        // Backslashes aren't special here.
        escaped.append(backslashes, '\\');
        escaped.push_back(*iterator);
      }
    }

    escaped.push_back(L'"');
  }

  return escaped;
}

// Concatenates multiple command-line arguments and escaps the values. If `arg`
// is not specified (or takes the value `0`), the function will scan `argv`
// until a `NULL` is encountered.
inline std::string stringify_args(const char** argv, unsigned long argc = 0)
{
  std::string arg_line = "";
  unsigned long index = 0;
  while ((argc < 0 || index < argc) && argv[index] != NULL) {
    arg_line = args(arg_line, escape_arg(argv[index]));
  }

  return arg_line;
}

// Concatenates multiple command-line arguments and escaps the values.
inline std::string stringify_args(const std::vector<string>& arguments)
{
  std::string arg_line = "";
  foreach(string arg, arguments) {
    arg_line = args(arg_line, escape_arg(arg));
  }

  return arg_line;
}

} // namespace os {

#endif // __STOUT_OS_WINDOWS_SHELL_HPP__
