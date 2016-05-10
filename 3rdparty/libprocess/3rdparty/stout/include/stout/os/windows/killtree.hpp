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

#ifndef __STOUT_OS_WINDOWS_KILLTREE_HPP__
#define __STOUT_OS_WINDOWS_KILLTREE_HPP__

#include <stdlib.h>

#include <stout/os/windows/process.hpp>

namespace os {

inline Try<std::list<ProcessTree>> pstree(pid_t pid)
{
  Try<std::list<Process>> processes = os::processes();

  if (processes.isError()) {
    return Error(processes.error());
  }

  Result<Process> process = os::process(pid, processes.get());

  std::queue<pid_t> queue;

  if (process.isNone()) {
        queue.push(pid);
  }

  // Root process is not running so nothing we can do.
  if (queue.empty()) {
    return std::list<ProcessTree>();
  }

  struct {
    std::set<pid_t> pids;
    std::list<Process> processes;
  } visited;


  while (!queue.empty()) {
    pid_t pid = queue.front();
    queue.pop();

    if (visited.pids.count(pid) != 0) {
      continue;
    }

    // Make sure this process still exists.
    process = os::process(pid);

    if (process.isError()) {
      return Error(process.error());
    } else if (process.isNone()) {
      continue;
    }

    visited.pids.insert(pid);
    visited.processes.push_back(process.get());

    // Enqueue the children for visiting.
    foreach (pid_t child, os::children(pid, processes.get(), false)) {
      queue.push(child);
    }
  // Return the process trees representing the visited pids.
  return pstrees(visited.pids, visited.processes);
}


// Termintat the process tree rooted at the specified pid.
// Note that if the process 'pid' has exited we'll terminate the process
// tree(s) rooted at pids
// Returns the process trees that were succesfully or unsuccessfully
// signaled. Note that the process trees can be stringified.
// TODO(benh): Allow excluding the root pid from stopping, killing,
// and continuing so as to provide a means for expressing "kill all of
// my children". This is non-trivial because of the current
// implementation.
inline Try<std::list<ProcessTree>> killtree(
    pid_t pid,
    int signal,
    bool groups = false,
    bool sessions = false)
{
  Try<std::list<ProcessTree>> process_tree = os::pstree(pid);

  Try<Nothing> kill_job = os::kill_job(pid);
  if (kill_job.isError())
  {
    return Error(kill_job.error());
  }
  return process_tree;
}
} // namespace os {

#endif // __STOUT_OS_WINDOWS_KILLTREE_HPP__
