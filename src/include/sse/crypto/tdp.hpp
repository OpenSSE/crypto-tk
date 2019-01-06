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
#include <sse/crypto/prf.hpp>

#include <cstdint>
#include <cstring>

#include <array>
#include <memory>
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
    /// @brief  Size (in bytes) of the PRF output used to pseudo-randomly
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
    /// @exception std::runtime_error   Parsing pk is an invalid RSA public key
    ///
    explicit Tdp(const std::string& pk);

    ///
    /// @brief  Copy constructor
    ///
    /// @param  t   The copied Tdp
    ///
    /// @exception std::runtime_error   Failed to copy the Tdp RSA public key
    ///
    Tdp(const Tdp& t);

    ///
    /// @brief  Assignement operator
    ///
    /// @param  t   The copied Tdp
    ///
    /// @exception std::runtime_error   Failed to copy the Tdp RSA public key
    ///
    Tdp& operator=(const Tdp& t);

    ///
    /// @brief  Destructor
    ///
    virtual ~Tdp();

    ///
    /// @brief Get the public key
    ///
    /// Creates and returns a string containing the public key of the TDP in the
    /// PEM format
    ///
    /// @return The public key in the PEM format
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
    /// Evaluates the TDP on the input message and writes the result to the
    /// output string
    ///
    /// @param  in  The input message, stored in a string
    /// @param  out The reference to the output string
    ///
    /// @exception std::runtime_error   Parsing in as a valid input failed
    ///
    void eval(const std::string& in, std::string& out) const;

    ///
    /// @brief Evaluate the TDP
    ///
    /// Evaluates the TDP on the input message and returns the result as a
    /// string
    ///
    /// @param  in  The input message, stored in a string
    /// @return     The result of the evaluation, stored in a string
    ///
    /// @exception std::runtime_error   Parsing in as a valid input failed
    ///
    std::string eval(const std::string& in) const;

    ///
    /// @brief Evaluate the TDP
    ///
    /// Evaluates the TDP on the input message and returns the result as a
    /// byte array
    ///
    /// @param  in  The input message, stored in a byte array
    /// @return     The result of the evaluation, stored in a byte array
    ///
    /// @exception std::runtime_error   Parsing in as a valid input failed
    ///
    std::array<uint8_t, kMessageSize> eval(
        const std::array<uint8_t, kMessageSize>& in) const;

private:
    std::unique_ptr<TdpImpl> tdp_imp_; // opaque pointer
};

/// @class TdpInverse
/// @brief Trapdoor permutation (public and private-key operations).
///
/// Tdp is an opaque class implementing both the private and public key
/// operations of a trapdoor permutation (TDP). It is currently based on RSA.
///
/// It does not derive from the class Tdp on purpose: it ensures very strong
/// type safety between the public and the private key operations.
///
class TdpInverse
{
    friend class Wrapper;

public:
    /// @brief  Size (in bytes) of a message (i.e. the elements on which the TDP
    ///         operates). It is also the size of the RSA modulus.
    static constexpr size_t kMessageSize = Tdp::kMessageSize;

    /// @brief  Size (in bytes) of the public context (used to wrap a Prg
    ///         object).
    static constexpr size_t kPublicContextSize = 0;


    /// @brief The public context of a Prp object. It is an empty array.
    static constexpr std::array<uint8_t, kPublicContextSize> public_context()
    {
        // GCC (4.8) does not support using {} instead of
        // std::array<uint8_t, kPublicContextSize>()
        // NOLINTNEXTLINE(modernize-return-braced-init-list)
        return std::array<uint8_t, kPublicContextSize>();
    }

    ///
    /// @brief  Constructor
    ///
    /// Constructs a TdpInverse object from a new randomly generated RSA private
    /// key.
    ///
    /// @exception std::runtime_error   The RSA key generation failed
    ///
    TdpInverse();

    ///
    /// @brief  Constructor
    ///
    /// Constructs a Tdp object from an RSA private key. The public key has to
    /// be in the PKCS #8 PEM format.
    ///
    /// @param  sk  String storing a private key in PEM format
    ///
    /// @exception std::runtime_error   The input RSA key is invalid
    ///
    explicit TdpInverse(const std::string& sk);

    TdpInverse(const TdpInverse& tdp) = delete;
    TdpInverse(TdpInverse&& tdp)      = default;

    TdpInverse& operator=(const TdpInverse& t) = delete;

    ///
    /// @brief Destructor
    ///
    ~TdpInverse();

    ///
    /// @brief Get the public key
    ///
    /// Creates and returns a string containing the public key of the TDP in the
    /// PEM format
    ///
    /// @return The public key in the PEM format
    ///
    std::string public_key() const;

    ///
    /// @brief Get the private key
    ///
    /// Creates and returns a string containing the private key of the TDP in
    /// the PKCS #8 PEM format
    ///
    /// @return The private key in the PKCS #8 PEM format
    ///
    std::string private_key() const;

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
    /// Evaluates the TDP on the input message and writes the result to the
    /// output string
    ///
    /// @param  in  The input message, stored in a string
    /// @param  out The reference to the output string
    ///
    /// @exception std::runtime_error   Parsing in as a valid input failed
    ///
    void eval(const std::string& in, std::string& out) const;

    ///
    /// @brief Evaluate the TDP
    ///
    /// Evaluates the TDP on the input message and returns the result as a
    /// string
    ///
    /// @param  in  The input message, stored in a string
    /// @return     The result of the evaluation, stored in a string
    ///
    /// @exception std::runtime_error   Parsing in as a valid input failed
    ///
    std::string eval(const std::string& in) const;

    ///
    /// @brief Evaluate the TDP
    ///
    /// Evaluates the TDP on the input message and returns the result as a
    /// byte array
    ///
    /// @param  in  The input message, stored in a byte array
    /// @return     The result of the evaluation, stored in a byte array
    ///
    /// @exception std::runtime_error   Parsing in as a valid input failed
    ///
    std::array<uint8_t, kMessageSize> eval(
        const std::array<uint8_t, kMessageSize>& in) const;

    ///
    /// @brief Invert the TDP (private-key operation)
    ///
    /// Evaluates the inverse of the TDP on the input message and writes the
    /// result to the output string
    ///
    /// @param  in  The input message, stored in a string
    /// @param  out The reference to the output string
    ///
    /// @exception std::runtime_error   Parsing in as a valid input failed
    ///
    void invert(const std::string& in, std::string& out) const;

    ///
    /// @brief Invert the TDP (private-key operation)
    ///
    /// Evaluates the inverse of the TDP on the input message and returns the
    /// result as a string
    ///
    /// @param  in  The input message, stored in a string
    /// @return     The result of the inversion, stored in a string
    ///
    /// @exception std::runtime_error   Parsing in as a valid input failed
    ///
    std::string invert(const std::string& in) const;

    ///
    /// @brief Invert the TDP (private-key operation)
    ///
    /// Evaluates the inverse of the TDP on the input message and returns the
    /// result as a byte array
    ///
    /// @param  in  The input message, stored in a byte array
    /// @return     The result of the inversion, stored in a byte array
    ///
    /// @exception std::runtime_error   Parsing in as a valid input failed
    ///
    std::array<uint8_t, kMessageSize> invert(
        const std::array<uint8_t, kMessageSize>& in) const;

    ///
    /// @brief Invert the TDP multiple times
    ///
    /// Evaluates the inverse of the TDP on the input message order times (i.e.
    /// compute \f$ \pi_{SK}^{-order}(in)\f$) and writes the result to a string
    ///
    /// @param  in      The input message, stored in a string
    /// @param  order   The number of times the inverse TDP is iterated on in
    /// @param  out     The reference to the output string
    ///
    /// @exception std::runtime_error   Parsing in as a valid input failed
    ///
    void invert_mult(const std::string& in,
                     std::string&       out,
                     uint32_t           order) const;
    ///
    /// @brief Invert the TDP multiple times
    ///
    /// Evaluates the inverse of the TDP on the input message order times (i.e.
    /// compute \f$ \pi_{SK}^{-order}(in)\f$) and returns the result as a string
    ///
    /// @param  in      The input message, stored in a string
    /// @param  order   The number of times the inverse TDP is iterated on in
    /// @return         The result of the inversion, stored in a string
    ///
    /// @exception std::runtime_error   Parsing in as a valid input failed
    ///
    std::string invert_mult(const std::string& in, uint32_t order) const;

    ///
    /// @brief Invert the TDP multiple times
    ///
    /// Evaluates the inverse of the TDP on the input message order times (i.e.
    /// compute \f$ \pi_{SK}^{-order}(in)\f$) and returns the result as a byte
    /// array
    ///
    /// @param  in      The input message, stored in a byte array
    /// @param  order   The number of times the inverse TDP is iterated on in
    /// @return         The result of the inversion, stored in a byte array
    ///
    /// @exception std::runtime_error   Parsing in as a valid input failed
    ///
    std::array<uint8_t, kMessageSize> invert_mult(
        const std::array<uint8_t, kMessageSize>& in,
        uint32_t                                 order) const;

private:
    std::unique_ptr<TdpInverseImpl> tdp_inv_imp_; // opaque pointer


    /// @brief  Returns the size (in bytes) of the serialized representation of
    ///         the object
    ///
    /// @return The size in bytes of the buffer needed to serialize the object.
    ///
    size_t serialized_size() const noexcept
    {
        return private_key().size();
    }

    /// @brief Serialize the object in the given buffer
    ///
    /// @param[out] out The serialization buffer. It must be
    ///                 at least kSerializedSize bytes large.

    ///
    void serialize(uint8_t* out) const;

    /// @brief Deserialize a buffer into a Tdp object
    ///
    /// This static function constructs a new Tdp object out of the binary
    /// representation of the input buffer in. The in buffer must be at least
    /// kSerializedSize bytes large.
    ///
    /// @param  in      The byte buffer containing the binary representation of
    ///                 the Tdp object.
    /// @param  in_size The size of the in buffer.
    /// @param  n_bytes_read    The number of bytes from in read during the
    ///                         deserialization
    ///
    /// @exception  std::runtime_error Error when loading the RSA key.
    static TdpInverse deserialize(uint8_t*     in,
                                  const size_t in_size,
                                  size_t&      n_bytes_read);
};

/// @class TdpMultPool
/// @brief Trapdoor permutation (public-key operations) with precomputations for
/// fast iterative evaluation.
///
/// TdpMultPool is an opaque class implementing a the public key operations of a
/// trapdoor permutation (TDP), and which does pre-computations to be able to
/// quickly compute multiple iterative evaluations of the permutation (\f$
/// \pi_{PK}^{c}(x)\f$). It is currently based on RSA.
///
class TdpMultPool
{
public:
    /// @brief  Size (in bytes) of a message (i.e. the elements on which the TDP
    ///         operates). It is also the size of the RSA modulus.
    static constexpr size_t kMessageSize = Tdp::kMessageSize;

    ///
    /// @brief  Constructor
    ///
    /// Constructs a TdpMultPool object from an RSA public key, and with a given
    /// size. The public key has to be in the PEM format.
    ///
    /// @param  pk      String storing a public key in PEM format.
    /// @param  size    Size of the pool (i.e. the maximum order of the TDP
    ///                 evaluation). Must be strictly positive
    ///
    /// @exception std::runtime_error       Parsing pk is an invalid RSA public
    ///                                     key
    ///
    /// @exception std::invalid_argument    size is 0
    ///
    TdpMultPool(const std::string& pk, const uint8_t size);

    ///
    /// @brief  Copy constructor
    ///
    /// @param  pool    The copied Tdp pool
    ///
    /// @exception std::runtime_error   Failed to copy the TdpPool RSA key
    ///
    TdpMultPool(const TdpMultPool& pool);

    ///
    /// @brief  Assignement operator
    ///
    /// @param  t   The copied Tdp pool
    ///
    /// @exception std::runtime_error   Failed to copy the TdpPool RSA key
    ///
    TdpMultPool& operator=(const TdpMultPool& t);

    ///
    /// @brief  Destructor
    ///
    virtual ~TdpMultPool();

    ///
    /// @brief Get the public key
    ///
    /// Creates and returns a string containing the public key of the TDP in the
    /// PEM format
    ///
    /// @return The public key in the PEM format
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
    /// Evaluates the TDP on the input message and writes the result to the
    /// output string
    ///
    /// @param  in  The input message, stored in a string
    /// @param  out The reference to the output string
    ///
    /// @exception std::runtime_error   Parsing in as a valid input failed
    ///
    void eval(const std::string& in, std::string& out) const;

    ///
    /// @brief Evaluate the TDP
    ///
    /// Evaluates the TDP on the input message and returns the result as a
    /// string
    ///
    /// @param  in  The input message, stored in a string
    /// @return     The result of the evaluation, stored in a string
    ///
    /// @exception std::runtime_error   Parsing in as a valid input failed
    ///
    std::string eval(const std::string& in) const;

    ///
    /// @brief Evaluate the TDP
    ///
    /// Evaluates the TDP on the input message and returns the result as a
    /// byte array
    ///
    /// @param  in  The input message, stored in a byte array
    /// @return     The result of the evaluation, stored in a byte array
    ///
    /// @exception std::runtime_error   Parsing in as a valid input failed
    ///
    std::array<uint8_t, kMessageSize> eval(
        const std::array<uint8_t, kMessageSize>& in) const;

    ///
    /// @brief Iteratively evaluate the TDP
    ///
    /// Iteratively evaluates the TDP on the input message order times (i.e.
    /// compute \f$ \pi_{PK}^{order}(in)\f$) and writes the result to the output
    /// string
    ///
    /// @param  in      The input message, stored in a string
    /// @param  out     The reference to the output string
    /// @param  order   The number of times the TDP evaluation is iterated on in
    ///
    /// @exception std::runtime_error   Parsing in as a valid input failed
    ///
    void eval(const std::string& in, std::string& out, uint8_t order) const;

    ///
    /// @brief Iteratively evaluate the TDP
    ///
    /// Iteratively evaluates the TDP on the input message order times (i.e.
    /// compute \f$ \pi_{PK}^{order}(in)\f$) and return the result as a string
    ///
    /// @param  in      The input message, stored in a string
    /// @param  order   The number of times the TDP evaluation is iterated on in
    /// @return         The result of the iterated evaluation, stored in a
    ///                 string
    ///
    /// @exception std::runtime_error   Parsing in as a valid input failed
    ///
    std::string eval(const std::string& in, uint8_t order) const;

    ///
    /// @brief Iteratively evaluate the TDP
    ///
    /// Iteratively evaluates the TDP on the input message order times (i.e.
    /// compute \f$ \pi_{PK}^{order}(in)\f$) and return the result as a byte
    /// array
    ///
    /// @param  in      The input message, stored in byte array
    /// @param  order   The number of times the TDP evaluation is iterated on in
    /// @return         The result of the iterated evaluation, stored in a
    ///                 byte array
    ///
    /// @exception std::invalid_argument    order is larger than the maximum
    ///                                     supported order (as returned by
    ///                                     TdpMultPool::maximum_order()
    /// @exception std::runtime_error       Parsing in as a valid input failed
    ///
    std::array<uint8_t, kMessageSize> eval(
        const std::array<uint8_t, kMessageSize>& in,
        uint8_t                                  order) const;

    ///
    /// @brief  Maximum evaluation order supported by the pool
    ///
    /// Return the maximum order supported by calls to the eval method of the
    /// pool. It is the size of the pool.
    ///
    /// @return The maximum evaluation order.
    ///
    uint8_t maximum_order() const;

private:
    std::unique_ptr<TdpMultPoolImpl> tdp_pool_imp_; // opaque pointer
};

///
/// @} // end of group tdp
///


} // namespace crypto
} // namespace sse
