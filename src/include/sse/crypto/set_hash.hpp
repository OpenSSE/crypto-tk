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

#include <array>
#include <string>
#include <vector>

namespace sse {

namespace crypto {

///
/// @class SetHash
/// @brief Incremental set hashing
///
/// SetHash implements a (multi)set hash function (cf. *Incremental Multiset
/// Hash Functions and Their Application to Memory Integrity Checking* --
/// https://people.csail.mit.edu/devadas/pubs/mhashes.pdf ). It allows to
/// compute the hash of a set of elements, without accounting for the order in
/// which the elements are hashed. Also, it is easy to compute to the hash of
/// \f$S \cup \{x\}\f$ given the hash of S (it can be done in constant time,
/// without having to enumerate all the elements in S). Same thing for the
/// suppression of \f$x \in S\f$.
///
/// This implementation uses the elliptic curve multiset hash (ECMH) by by
/// Maitin-Shepard, Tibouchi and Aranha (see https://arxiv.org/abs/1601.06502 )
/// implemented on Ed25519 using libsodium's Elligator primitives introduced in
/// libsodium 1.0.16
///
/// The sets that can be hashed are sets of std::string.
///
class SetHash
{
public:
    /// @brief Size of the bytes representation of a SetHash
    static constexpr size_t kSetHashSize = 32;

    /// @brief The infinite curve point, representing an empty set.
    static constexpr std::array<uint8_t, kSetHashSize> kECInfinitePoint
        = {{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

    ///
    /// @brief Constructor
    ///
    /// Creates and initializes a SetHash for an empty set.
    ///
    // the initial state is the infinite point
    // we directly copy kECInfinitePoint: calling
    // crypto_scalarmult_ed25519_base(set_hash_state_, scalar_zero__)
    // will generate a differente byte string as the one obtained by computing
    // crypto_core_ed25519_sub(_,b,b) (computing b-b). Indeed,
    // crypto_core_ed25519_sub(x,b,b) sets x to kECInfinitePoint.
    SetHash() = default;

    ///
    /// @brief Constructor
    ///
    /// Creates a new SetHash from an already computed hash, in its hexadecimal
    /// representation
    ///
    /// @param bytes A bytes array representing a set hash.
    ///
    explicit SetHash(const std::array<uint8_t, kSetHashSize>& bytes);

    ///
    /// @brief Copy constructor
    ///
    SetHash(const SetHash& o) = default;

    ///
    /// @brief Move constructor
    ///
    SetHash(SetHash&& o) noexcept = default;

    ///
    /// @brief Constructor
    ///
    /// Creates a new SetHash representing a vector (list) of strings
    ///
    /// @param in_set   The elements to be hashed.
    ///
    explicit SetHash(const std::vector<std::string>& in_set);


    ///
    /// @brief Hash a new element in the set hash
    ///
    /// Compute the hash of \f$S \cup \{in\} \f$ where S is the set represented
    /// by the object.
    ///
    /// @param in   The element to insert
    ///
    void add_element(const std::string& in);

    ///
    /// @brief Compute the hash of a union
    ///
    /// Compute the hash of \f$S \cup S'\f$ where S is the set represented by
    /// the object, and S' the set represented by h.
    ///
    /// @param h    The set hash of the set to insert in the target object
    ///
    void add_set(const SetHash& h);


    ///
    /// @brief Remove an element of the set hash
    ///
    /// Compute the hash of \f$S \setminus \{in\} \f$ where S is the set
    /// represented by the object.
    ///
    /// @param in   The element to insert
    ///
    void remove_element(const std::string& in);

    ///
    /// @brief Compute the hash of a set difference
    ///
    /// Compute the hash of \f$S \setminus S'\f$ where S is the set represented
    /// by the object, and S' the set represented by h.
    ///
    /// @param h    The set hash of the set to remove from the target object
    ///
    void remove_set(const SetHash& h);

    ///
    /// @brief Binary representation of the SetHash
    ///
    /// Returns a bytes array containing the representation of the
    /// SetHash object.
    ///
    /// @return The array representing the set hash
    ///
    const std::array<uint8_t, kSetHashSize>& data() const;


    ///
    /// @brief Stream serialization operator
    ///
    /// Put the hex string representation of a SetHash in an output stream.
    ///
    /// @param os   The output stream
    /// @param h    The set hash to serialize in the stream
    ///
    /// @return     The stream os
    ///
    friend std::ostream& operator<<(std::ostream& os, const SetHash& h);

    ///
    /// @brief Assignment operator
    ///
    /// @param h    The element to assign
    /// @return     The assigned object
    ///
    SetHash& operator=(const SetHash& h) = default;

    ///
    /// @brief Comparison operator
    ///
    /// Compare set hashes. The comparison is done in constant time.
    ///
    /// @param h    The element to compare
    /// @return     true if h and the object have the same hash, false otherwise
    ///
    bool operator==(const SetHash& h) const;

    ///
    /// @brief Comparison operator
    /// @param h    The element to compare
    /// @return     false if h and the object have the same hash,
    ///             true otherwise. The comparison is done in constant time
    ///
    bool operator!=(const SetHash& h) const;

private:
    static void gen_curve_point(std::array<uint8_t, kSetHashSize>& p,
                                const uint8_t*                     buf,
                                const size_t                       len);

    std::array<uint8_t, kSetHashSize> set_hash_state_ = kECInfinitePoint;
};

} // namespace crypto
} // namespace sse
