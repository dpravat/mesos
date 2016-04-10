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

#include <gtest/gtest.h>

#include <stout/os.hpp>

#include <stout/tests/utils.hpp>

using std::string;


class EnvTest : public TemporaryDirectoryTest {};


TEST(EnvTest, SimpleEnvTest)
{
  const string env_key = "simple_env_key";
  const string env_value_1 = "simple_env_value";

  // Key currently does not exist in process environment.
  EXPECT_NONE(os::getenv(env_key));

  // Set environment variable, check that it is there now.
  os::setenv(env_key, env_value_1, false);
  Option<string> result = os::getenv(env_key);
  ASSERT_SOME(result);
  EXPECT_EQ(env_value_1, result.get());

  // Verify that if we set the environment variable without the `overwrite`
  // flag set, the value of that variable was not updated.
  const string env_value_2 = "new_favorite_value";
  os::setenv(env_key, env_value_2, false);
  result = os::getenv(env_key);
  ASSERT_SOME(result);
  EXPECT_EQ(env_value_1, result.get());

  // Now set environment variable, and set `overwrite` flag.
  os::setenv(env_key, env_value_2, true);
  result = os::getenv(env_key);
  ASSERT_SOME(result);
  EXPECT_EQ(env_value_2, result.get());

  // Now verify that the default behavior sets the `overwrite` flag to true.
  const string env_value_3 = "even_newer_favorite_value";
  os::setenv(env_key, env_value_3);
  result = os::getenv(env_key);
  ASSERT_SOME(result);
  EXPECT_EQ(env_value_3, result.get());

  // Finally, unset the variable.
  os::unsetenv(env_key);
  result = os::getenv(env_key);
  EXPECT_NONE(result);
}
