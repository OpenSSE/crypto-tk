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

#include <exception>
#include <iostream>

#include "gtest/gtest.h"

//  Google Test takes care of everything
//  Tests are automatically registered and run

int main(int argc, char* argv[])
{
    try {
        sse::crypto::init_crypto_lib();
    } catch (const std::runtime_error& e) {
        std::cerr
            << "Error during the initialization of the cryptographic library:\n"
            << e.what();
        return -1;
    }
    ::testing::InitGoogleTest(&argc, argv);
    int rv = RUN_ALL_TESTS();

    sse::crypto::cleanup_crypto_lib();

    return rv;
}
