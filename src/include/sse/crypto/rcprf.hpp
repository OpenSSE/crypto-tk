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


#pragma once

#include <sse/crypto/key.hpp>
#include <sse/crypto/prg.hpp>

#include <cassert>

#include <exception>
#include <iostream>

namespace sse {
namespace crypto {

enum RCPrfTreeNodeChild : uint8_t
{
    LeftChild  = 0,
    RightChild = 1
};

static inline RCPrfTreeNodeChild get_child(uint8_t  tree_height,
                                           uint64_t leaf,
                                           uint8_t  node_depth)
{
    uint64_t mask = 1UL << (tree_height - node_depth - 1);

    return ((leaf & mask) == 0) ? LeftChild : RightChild;
}


/// @class RCPrf
/// @brief Range-Constrained Pseudorandom function.
///
/// The RCPrf templates realizes a range-constrained pseudorandom function
/// (RC-PRF) using a tree-based construction, and the library's built-in PRF.
///
/// Similarly to the PRF class, it is templated according to the output length
/// to avoid key-reuse vulnerabilities.
///
/// @tparam NBYTES  The output size (in bytes)
///
template<uint16_t NBYTES>
class RCPrf
{
public:
    static constexpr uint8_t kKeySize = 32;
    using depth_type                  = uint8_t;

    ///
    /// @brief Constructor
    ///
    /// Creates a RCPrf object from a kKeySize (32) bytes key, with the
    /// specified tree height. After a call to the constructor, the input key
    /// is held by the RCPrf object, and cannot be re-used.
    ///
    /// @param key   The key used to initialize the PRF.
    ///              Upon return, k is empty
    ///
    /// @param height The height of the RC-PRF tree. The returned RCPrf object
    ///              will be able to evaluate integer input from 0 to
    ///              2^height -1. height must be larger than 1 and less than 64
    ///
    /// @exception std::invalid_argument       height is not between 1 and 64
    ///
    RCPrf(Key<kKeySize>&& key, depth_type height)
        : root_prg_(std::move(key)), tree_height_(height)
    {
        if (height == 0) {
            throw std::invalid_argument(
                "Invalid height: height must be non-zero");
        }
        if (height > 64) {
            throw std::invalid_argument(
                "Invalid height: height must be less than 64");
        }
    }

    ///
    /// @brief Evaluate the RC-PRF
    ///
    /// Evaluates the RC-PRF on the input by deriving the i-th leave of the tree
    /// and places the result in an array.
    ///
    ///
    /// @param leaf The index of the leaf to derive. Must be less or equal than
    ///             2^height -1.
    ///
    /// @return     An std::array of NBYTES bytes containing the result of the
    ///             evaluation
    ///
    /// @exception std::invalid_argument       leaf is larger than 2^height-1
    ///
    std::array<uint8_t, NBYTES> eval(uint64_t leaf) const;


private:
    Prg              root_prg_;
    const depth_type tree_height_;
};

template<uint16_t NBYTES>
std::array<uint8_t, NBYTES> RCPrf<NBYTES>::eval(uint64_t leaf) const
{
    if (leaf >> tree_height_ != 0) {
        throw std::invalid_argument("Invalid node index: leaf > 2^height -1.");
    }

    // the first step is done from the root PRG
    RCPrfTreeNodeChild child = get_child(tree_height_, leaf, 0);
    Key<kKeySize>      subkey
        = root_prg_.derive_key<kKeySize>(static_cast<uint16_t>(child));

    // now proceed with the subkeys until we reach the leaf's parent
    for (uint8_t i = 1; i < tree_height_ - 1;
         i++, child = get_child(tree_height_, leaf, i)) {
        subkey = Prg::derive_key<kKeySize>(std::move(subkey),
                                           static_cast<uint16_t>(child));
    }

    std::array<uint8_t, NBYTES> result;

    // finish by evaluating the leaf
    Prg::derive(std::move(subkey),
                static_cast<uint32_t>(child) * NBYTES,
                NBYTES,
                result.data());

    return result;
}

} // namespace crypto
} // namespace sse