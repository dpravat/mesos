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

#include <list>
#include <string>

#include <stout/fs.hpp>
#include <stout/os.hpp>
#include <stout/path.hpp>

#include "slave/paths.hpp"

#include "slave/containerizer/mesos/isolators/filesystem/windows.hpp"

using namespace process;

using std::list;
using std::string;

using mesos::slave::ContainerConfig;
using mesos::slave::ContainerLaunchInfo;
using mesos::slave::ContainerLimitation;
using mesos::slave::ContainerState;
using mesos::slave::Isolator;

namespace mesos {
namespace internal {
namespace slave {

WindowsFilesystemIsolatorProcess::WindowsFilesystemIsolatorProcess(
    const Flags& _flags)
  : flags(_flags) {}


WindowsFilesystemIsolatorProcess::~WindowsFilesystemIsolatorProcess() {}


Try<Isolator*> WindowsFilesystemIsolatorProcess::create(const Flags& flags)
{
  process::Owned<MesosIsolatorProcess> process(
      new WindowsFilesystemIsolatorProcess(flags));

  return new MesosIsolator(process);
}


Future<Nothing> WindowsFilesystemIsolatorProcess::recover(
    const list<ContainerState>& states,
    const hashset<ContainerID>& orphans)
{
  foreach (const ContainerState& state, states) {
    infos.put(state.container_id(), Owned<Info>(new Info(state.directory())));
  }

  return Nothing();
}


Future<Option<ContainerLaunchInfo>> WindowsFilesystemIsolatorProcess::prepare(
    const ContainerID& containerId,
    const ContainerConfig& containerConfig)
{
  if (infos.contains(containerId)) {
    return Failure("Container has already been prepared");
  }

  const ExecutorInfo& executorInfo = containerConfig.executorinfo();

  if (executorInfo.has_container()) {
    CHECK_EQ(executorInfo.container().type(), ContainerInfo::MESOS);

    // Return failure if the container change the filesystem root
    // because the symlinks will become invalid in the new root.
    if (executorInfo.container().mesos().has_image()) {
      return Failure("Container root filesystems not supported");
    }

    if (executorInfo.container().volumes().size() > 0) {
      return Failure("Volumes in ContainerInfo is not supported");
    }
  }

  infos.put(containerId, Owned<Info>(new Info(containerConfig.directory())));

  return update(containerId, executorInfo.resources())
      .then([]() -> Future<Option<ContainerLaunchInfo>> { return None(); });
}


Future<Nothing> WindowsFilesystemIsolatorProcess::isolate(
    const ContainerID& containerId,
    pid_t pid)
{
  // No-op.
  return Nothing();
}


Future<ContainerLimitation> WindowsFilesystemIsolatorProcess::watch(
    const ContainerID& containerId)
{
  // No-op.
  return Future<ContainerLimitation>();
}


Future<Nothing> WindowsFilesystemIsolatorProcess::update(
    const ContainerID& containerId,
    const Resources& resources)
{
  if (!infos.contains(containerId)) {
    return Failure("Unknown container");
  }

  const Owned<Info>& info = infos[containerId];

  // Store the updated resources.
  info->resources = resources;

  return Nothing();
}


Future<ResourceStatistics> WindowsFilesystemIsolatorProcess::usage(
    const ContainerID& containerId)
{
  // No-op, no usage gathered.
  return ResourceStatistics();
}


Future<Nothing> WindowsFilesystemIsolatorProcess::cleanup(
    const ContainerID& containerId)
{
  // Symlinks for persistent resources will be removed when the work
  // directory is GC'ed, therefore no need to do explicit cleanup.
  infos.erase(containerId);

  return Nothing();
}

} // namespace slave {
} // namespace internal {
} // namespace mesos {
