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

#include "key.hpp"
#include "prf.hpp"

#include <cstdint>

#include <array>
#include <string>

namespace sse {
namespace crypto {

/// @file tdp.hpp
///
/// Construction of trapdoor permutations

/// @defgroup tdp Trapdoor Permutation
///
/// Define and construct trapdoor permutations
///
/// @{
///

class TdpImpl;         // not defined in the header
class TdpInverseImpl;  // not defined in the header
class TdpMultPoolImpl; // not defined in the header


/// @class Tdp
/// @brief Trapdoor permutation (public-key operations).
///
/// Tdp is an opaque class implementing a the public key operations of a
/// trapdoor permutation (TDP). It is currently based on RSA.
///
class Tdp
{
public:
    /// @brief  Size (in bytes) of a message (i.e. the elements on which the TDP
    ///         operates). It is also the size of the RSA modulus.
    static constexpr size_t kMessageSize = 256;
    /// @brief  Statistical security level (in bits) used for the random
    ///         generation of messages.
    static constexpr unsigned int kStatisticalSecurity = 64;
    /// @brief  Size (in bytes) of the PRG output used to pseudo-randomly
    ///         generate messages.
    static constexpr size_t kRSAPrfSize
        = kMessageSize + (kStatisticalSecurity + 7) / 8;

    ///
    /// @brief  Constructor
    ///
    /// Constructs a Tdp object from an RSA public key. The public key has to be
    /// in the PEM format.
    ///
    /// @param  pk  String storing a public key in PEM format
    ///
    explicit Tdp(const std::string& pk);

    ///
    /// @brief  Copy constructor
    ///
    /// @param  t   The copied Tdp
    ///
    Tdp(const Tdp& t);

    ///
    /// @brief  Assignement operator
    ///
    /// @param  t   The copied Tdp
    ///
    Tdp& operator=(const Tdp& t);

    ///
    /// @brief  Destructor
    ///
    virtual ~Tdp();

    ///
    /// @brief Get the public
    ///
    /// Creates and returns a string containing the public key of the TDP in the
    /// PEM format
    ///
    /// @return The public key in PEM format
    ///
    std::string public_key() const;

    ///
    /// @brief Randomly sample a message
    ///
    /// Returns a random valid message for the TDP, that is the string binary
    /// representation of an integer modulo N, where N is the public modulus of
    /// the RSA instance represented by the TDP.
    ///
    /// @return A string storing a random message
    ///
    std::string sample() const;

    ///
    /// @brief Randomly sample a message
    ///
    /// Returns a random valid message for the TDP, that is the binary
    /// representation of an integer modulo N stored in an array, where N is the
    /// public modulus of the RSA instance represented by the TDP.
    ///
    /// @return An array of bytes storing a random message
    ///
    std::array<uint8_t, kMessageSize> sample_array() const;

    ///
    /// @brief Pseudo-randomly generate a message
    ///
    /// Returns a pseudo-randomly generated valid message for the TDP, that is
    /// the binary representation of an integer modulo N stored in an array,
    /// where N is the public modulus of the RSA instance represented by the
    /// TDP.
    /// As the generation of this integer is done deterministically, using a
    /// pseudo-random function keyed with key, evaluated on seed.
    ///
    /// @param  key     The key of the PRF used for the pseudo-random generation
    ///                 of the message. After a call to this function, key is
    ///                 empty.
    /// @param  seed    The value on which the PRF is evaluated
    ///
    /// @return A string storing a pseudo-random message
    ///
    std::string generate(Key<Prf<Tdp::kRSAPrfSize>::kKeySize>&& key,
                         const std::string&                     seed) const;

    ///
    /// @brief Pseudo-randomly generate a message
    ///
    /// Returns a pseudo-randomly generated valid message for the TDP, that is
    /// the string binary representation of an integer modulo N,
    /// where N is the public modulus of the RSA instance represented by the
    /// TDP.
    /// As the generation of this integer is done deterministically, using a
    /// pseudo-random function keyed with key, evaluated on seed.
    ///
    /// @param  key     The key of the PRF used for the pseudo-random generation
    ///                 of the message. After a call to this function, key is
    ///                 empty.
    /// @param  seed    The value on which the PRF is evaluated
    ///
    /// @return An array storing a pseudo-random message
    ///
    std::array<uint8_t, kMessageSize> generate_array(
        Key<Prf<Tdp::kRSAPrfSize>::kKeySize>&& key,
        const std::string&                     seed) const;

    ///
    /// @brief Pseudo-randomly generate a message
    ///
    /// Returns a pseudo-randomly generated valid message for the TDP, that is
    /// the binary representation of an integer modulo N stored in an array,
    /// where N is the public modulus of the RSA instance represented by the
    /// TDP.
    /// As the generation of this integer is done deterministically, using a
    /// pseudo-random function given as input, evaluated on seed.
    ///
    /// @param  prf     The PRF used for the pseudo-random generation
    ///                 of the message.
    /// @param  seed    The value on which the PRF is evaluated
    ///
    /// @return A string storing a pseudo-random message
    ///
    std::string generate(const Prf<Tdp::kRSAPrfSize>& prf,
                         const std::string&           seed) const;

    ///
    /// @brief Pseudo-randomly generate a message
    ///
    /// Returns a pseudo-randomly generated valid message for the TDP, that is
    /// the string binary representation of an integer modulo N,
    /// where N is the public modulus of the RSA instance represented by the
    /// TDP.
    /// As the generation of this integer is done deterministically, using a
    /// pseudo-random function given as input, evaluated on seed.
    ///
    /// @param  prf     The PRF used for the pseudo-random generation
    ///                 of the message.
    /// @param  seed    The value on which the PRF is evaluated
    ///
    /// @return An array storing a pseudo-random message
    ///
    std::array<uint8_t, kMessageSize> generate_array(
        const Prf<Tdp::kRSAPrfSize>& prf,
        const std::string&           seed) const;


    ///
    /// @brief Evaluate the TDP
    ///
    /// Evaluates the TDP on the input message and writes the result in the
    /// output string
    ///
    /// @param  in  The input message, stored in a string
    /// @param  out The reference to the output string
    ///
    void        eval(const std::string& in, std::string& out) const;

    ///
    /// @brief Evaluate the TDP
    ///
    /// Evaluates the TDP on the input message and return the result as a
    /// string
    ///
    /// @param  in  The input message, stored in a string
    /// @return     The result of the evaluation, stored in a string
    ///
    std::string eval(const std::string& in) const;
    
    ///
    /// @brief Evaluate the TDP
    ///
    /// Evaluates the TDP on the input message and return the result as a
    /// byte array
    ///
    /// @param  in  The input message, stored in a byte array
    /// @return     The result of the evaluation, stored in a byte array
    ///
    std::array<uint8_t, kMessageSize> eval(
        const std::array<uint8_t, kMessageSize>& in) const;

private:
    TdpImpl* tdp_imp_; // opaque pointer
};

class TdpInverse
{
public:
    static constexpr size_t kMessageSize = Tdp::kMessageSize;

    TdpInverse();
    explicit TdpInverse(const std::string& sk);
    TdpInverse(const TdpInverse& tdp) = delete;
    TdpInverse(TdpInverse&& tdp)      = delete;

    TdpInverse& operator=(const TdpInverse& t) = delete;


    ~TdpInverse();

    std::string public_key() const;
    std::string private_key() const;

    std::string                       sample() const;
    std::array<uint8_t, kMessageSize> sample_array() const;

    std::string generate(Key<Prf<Tdp::kRSAPrfSize>::kKeySize>&& key,
                         const std::string&                     seed) const;
    std::array<uint8_t, kMessageSize> generate_array(
        Key<Prf<Tdp::kRSAPrfSize>::kKeySize>&& key,
        const std::string&                     seed) const;
    std::string                       generate(const Prf<Tdp::kRSAPrfSize>& prg,
                                               const std::string&           seed) const;
    std::array<uint8_t, kMessageSize> generate_array(
        const Prf<Tdp::kRSAPrfSize>& prg,
        const std::string&           seed) const;

    void        eval(const std::string& in, std::string& out) const;
    std::string eval(const std::string& in) const;
    std::array<uint8_t, kMessageSize> eval(
        const std::array<uint8_t, kMessageSize>& in) const;

    void        invert(const std::string& in, std::string& out) const;
    std::string invert(const std::string& in) const;
    std::array<uint8_t, kMessageSize> invert(
        const std::array<uint8_t, kMessageSize>& in) const;

    void        invert_mult(const std::string& in,
                            std::string&       out,
                            uint32_t           order) const;
    std::string invert_mult(const std::string& in, uint32_t order) const;
    std::array<uint8_t, kMessageSize> invert_mult(
        const std::array<uint8_t, kMessageSize>& in,
        uint32_t                                 order) const;

private:
    TdpInverseImpl* tdp_inv_imp_; // opaque pointer
};

class TdpMultPool
{
public:
    static constexpr size_t kMessageSize = Tdp::kMessageSize;

    TdpMultPool(const std::string& pk, const uint8_t size);
    TdpMultPool(const TdpMultPool& pool);

    TdpMultPool& operator=(const TdpMultPool& t);

    virtual ~TdpMultPool();

    std::string public_key() const;

    std::string                       sample() const;
    std::array<uint8_t, kMessageSize> sample_array() const;
    std::string generate(Key<Prf<Tdp::kRSAPrfSize>::kKeySize>&& key,
                         const std::string&                     seed) const;
    std::array<uint8_t, kMessageSize> generate_array(
        Key<Prf<Tdp::kRSAPrfSize>::kKeySize>&& key,
        const std::string&                     seed) const;
    std::string                       generate(const Prf<Tdp::kRSAPrfSize>& prg,
                                               const std::string&           seed) const;
    std::array<uint8_t, kMessageSize> generate_array(
        const Prf<Tdp::kRSAPrfSize>& prg,
        const std::string&           seed) const;

    void        eval(const std::string& in, std::string& out) const;
    std::string eval(const std::string& in) const;
    std::array<uint8_t, kMessageSize> eval(
        const std::array<uint8_t, kMessageSize>& in) const;

    void eval(const std::string& in, std::string& out, uint8_t order) const;
    std::string eval(const std::string& in, uint8_t order) const;
    std::array<uint8_t, kMessageSize> eval(
        const std::array<uint8_t, kMessageSize>& in,
        uint8_t                                  order) const;

    uint8_t maximum_order() const;
    uint8_t pool_size() const;

private:
    TdpMultPoolImpl* tdp_pool_imp_; // opaque pointer
};

///
/// @} // end of group tdp
///


} // namespace crypto
} // namespace sse
