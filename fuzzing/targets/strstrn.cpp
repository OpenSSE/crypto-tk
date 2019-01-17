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


// This function is defined in test_utility.hpp
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    for (size_t i = 0; i <= size; i++) {
        std::string s1(reinterpret_cast<const char*>(data), i);
        std::string s2(reinterpret_cast<const char*>(data + i), size - i);

        if (!test_strstrn(
                s1.c_str(), s1.length() + 1, s2.c_str(), s2.length() + 1)) {
            return -1;
        }
    }
    return 0;
}