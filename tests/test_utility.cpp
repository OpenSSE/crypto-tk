//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015-2017 Raphael Bost
//
// This file is part of libsse_crypto.
//
// libsse_crypto is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// libsse_crypto is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with libsse_crypto.  If not, see <http://www.gnu.org/licenses/>.
//

#include <sse/crypto/utils.hpp>

#include <cstring>

#include <string>

#include "gtest/gtest.h"


// str1 and str2 are NULL-terminated C-strings of length len1 and len2
// respectively (including the '\0' character)
// returns true iff strstr(str1,str2) and strstrn_uint8(str1, len1-1, str2,
// len2-1) are identical
bool test_strstrn(const char*  str1,
                  const size_t len1,
                  const char*  str2,
                  const size_t len2)
{
    // scan str1 and str2 to check that the \0 character is only at the last
    // location
    if (strchr(str1, '\0') != (str1 + len1 - 1)) {
        return true;
    }
    if (strchr(str2, '\0') != (str2 + len2 - 1)) {
        return true;
    }


    const char*    ref = strstr(str1, str2);
    const uint8_t* res
        = sse::crypto::strstrn_uint8(reinterpret_cast<const uint8_t*>(str1),
                                     len1 - 1,
                                     reinterpret_cast<const uint8_t*>(str2),
                                     len2 - 1);

    return ref == reinterpret_cast<const char*>(res);
}

bool test_strstrn(const std::string& s1, const std::string& s2)
{
    return test_strstrn(
        s1.c_str(), s1.length() + 1, s2.c_str(), s2.length() + 1);
}

TEST(utility, strstrn)
{
    EXPECT_TRUE(test_strstrn("", ""));
    EXPECT_TRUE(test_strstrn("", "a"));
    EXPECT_TRUE(test_strstrn("a", ""));

    EXPECT_TRUE(test_strstrn("baa", "b"));
    EXPECT_TRUE(test_strstrn("aba", "b"));
    EXPECT_TRUE(test_strstrn("aab", "b"));
    EXPECT_TRUE(test_strstrn("aaa", "b"));
    EXPECT_TRUE(test_strstrn("b", "aaa"));

    EXPECT_TRUE(test_strstrn("bbaa", "b"));
    EXPECT_TRUE(test_strstrn("baba", "b"));
    EXPECT_TRUE(test_strstrn("baab", "b"));
    EXPECT_TRUE(test_strstrn("abba", "b"));
    EXPECT_TRUE(test_strstrn("abab", "b"));
    EXPECT_TRUE(test_strstrn("aabb", "b"));

    EXPECT_TRUE(test_strstrn("bbaa", "bb"));
    EXPECT_TRUE(test_strstrn("baba", "bb"));
    EXPECT_TRUE(test_strstrn("baab", "bb"));
    EXPECT_TRUE(test_strstrn("abba", "bb"));
    EXPECT_TRUE(test_strstrn("abab", "bb"));
    EXPECT_TRUE(test_strstrn("aabb", "bb"));
}
