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

#ifndef __STOUT_FOREACH_HPP__
#define __STOUT_FOREACH_HPP__

#include <tuple>
#include <utility>

#include <boost/preprocessor/seq/cat.hpp>

#define FOREACH_ID(id) BOOST_PP_SEQ_CAT((__foreach_)(__LINE__)(_)(id)(__))

#define foreach(ELEM, ELEMS) for (ELEM : ELEMS)

#define foreachpair(KEY, VALUE, ELEMS)                                       \
  foreach (auto&& FOREACH_ID(elem), ELEMS)                                   \
    if (false) FOREACH_ID(break): break; else                                \
    if (bool FOREACH_ID(continue) = false); else                             \
    if (true) goto FOREACH_ID(body); else                                    \
    for (;;)                                                                 \
      if (FOREACH_ID(continue)) break; else                                  \
      if (true) goto FOREACH_ID(break); else                                 \
      FOREACH_ID(body):                                                      \
      if (bool FOREACH_ID(once) = false); else                               \
      for (KEY = std::get<0>(                                                \
              std::forward<decltype(FOREACH_ID(elem))>(FOREACH_ID(elem)));   \
           !FOREACH_ID(once);                                                \
           FOREACH_ID(once) = true)                                          \
        if ((FOREACH_ID(continue) = false)); else                            \
        for (VALUE = std::get<1>(                                            \
                std::forward<decltype(FOREACH_ID(elem))>(FOREACH_ID(elem))); \
             !FOREACH_ID(continue);                                          \
             FOREACH_ID(continue) = true)

#define foreachkey(KEY, ELEMS) foreachpair (KEY, std::ignore, ELEMS)

#define foreachvalue(VALUE, ELEMS) foreachpair (std::ignore, VALUE, ELEMS)

#endif // __STOUT_FOREACH_HPP__
