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

#ifndef __STOUT_RESULT_OF_HPP__
#define __STOUT_RESULT_OF_HPP__

#include <type_traits>

#ifndef __WINDOWS__
using std::result_of;
#else
// TODO(mpark): Swich back to simply using `std::result_of` this once we upgrade
// our Windows support to VS 2015 Update 2.

#include <utility>

namespace internal {

// A tag type that indicates substitution failure.
struct fail;


// Perform the necessary expression SFINAE in a context supported in VS 2015
// Update 1. Note that it leverages `std::invoke` which is carefully written to
// avoid the limitations around the partial expression SFINAE support.

template <typename, typename...>
fail result_of_type(...);


template <typename F, typename... Args>
auto result_of_type(int)
  -> decltype(std::invoke(std::declval<F>(), std::declval<Args>()...));


// `decltype(result_of_type<F, Args...>(0))` is either `fail` in the case of
// substitution failure, or the return type of `invoke(f, args...)`.
// `result_of_impl` provides a member typedef `type = R` only if `R != fail`.

template <typename T>
using result_of_impl = std::enable_if<!std::is_same<fail, T>::value, T>;


template <typename F>
struct result_of;  // undefined.


template <typename F, typename... Args>
struct result_of<F(Args...)>
  : result_of_impl<decltype(result_of_type<F, Args...>(0))> {};

} // namespace internal {

using internal::result_of;

#endif // __WINDOWS__

#endif // __STOUT_RESULT_OF_HPP__
