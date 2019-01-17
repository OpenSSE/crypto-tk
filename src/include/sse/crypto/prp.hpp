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

#include <cstdint>

#include <array>
#include <string>

namespace sse {
namespace crypto {

/// @class Prp
/// @brief Random permutation.
///
/// Prp is an opaque class implementing a length-preserving pseudorandom
/// permutation (PRP) for any input size. It uses the AEZ construction (by
/// Krovetz, Hoang and Rogaway). Because it relies on the reference
/// implementation, Prp requires support of AES-NI (on x86 CPUs) or of ARM NEON
/// instructions (or ARM CPUs). See the is_available static function to check
/// for availability.
///

class Prp
{
    friend class Wrapper;

public:
    /// @internal
    friend void init_crypto_lib();

    /// @brief Prp key size (in bytes)
    static constexpr uint8_t kKeySize = 48;

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
    /// @brief Check availability of the Prp class
    ///
    /// Checks if the Prp class is available, i.e. that the code have been
    /// compiled with AES-NI or ARM NEON instructions enabled, and that these
    /// instructions are indeed available on the host CPU.
    ///
    /// @return true if the Prp class can be used, false otherwise.
    ///
    inline static bool is_available() noexcept
    {
        return is_available__;
    }

    ///
    /// @brief Constructor
    ///
    /// Creates a PRP with a new randomly generated key.
    ///
    /// @exception std::runtime_error The Prp class is not available.
    ///
    Prp();

    ///
    /// @brief Constructor
    ///
    /// Creates a PRP from a 48 bytes (384 bits) key.
    /// After a call to the constructor, the input key is
    /// held by the Prp object, and cannot be re-used.
    ///
    /// @param k    The key used to initialize the PRP.
    ///             Upon return, k is empty
    ///
    /// @exception std::runtime_error The Prp class is not available.
    ///
    explicit Prp(Key<kKeySize>&& k);

    // we should not be able to duplicate Fpe objects
    Prp(const Prp& c) = delete;
    Prp(Prp& c)       = delete;

    ///
    /// @brief Move constructor
    ///
    /// @brief c The Prp object to be moved
    ///
    Prp(Prp&& c) noexcept = default;

    ///
    /// @brief PRP evaluation
    ///
    /// Evaluates the pseudo random permutation on the input string.
    ///
    /// @param in    The input of the PRP.
    /// @param out   The evaluation of PRP(in).
    ///
    /// @exception std::runtime_error The Prp class is not available.
    ///
    void encrypt(const std::string& in, std::string& out);

    ///
    /// @brief PRP evaluation
    ///
    /// Evaluates the pseudo random permutation on the input string.
    ///
    /// @param in    The input of the PRP.
    /// @return      The evaluation of PRP(in).
    ///
    /// @exception std::runtime_error The Prp class is not available.
    ///
    std::string encrypt(const std::string& in);

    ///
    /// @brief PRP evaluation
    ///
    /// Evaluates the pseudo random permutation on the input 32 bits integer.
    ///
    /// @param in    The input of the PRP.
    /// @return      The evaluation of PRP(in).
    ///
    /// @exception std::runtime_error The Prp class is not available.
    ///
    uint32_t encrypt(const uint32_t in);

    ///
    /// @brief PRP evaluation
    ///
    /// Evaluates the pseudo random permutation on a buffer.
    ///
    /// @param in           The input of the PRP.
    /// @param len          The length of the in buffer.
    /// @param[out] out     The output of the PRP evaluation.
    ///
    /// @exception std::runtime_error The Prp class is not available.
    ///

    void encrypt(const uint8_t* in, const unsigned int len, uint8_t* out);
    ///
    /// @brief PRP evaluation
    ///
    /// Evaluates the pseudo random permutation on the input 64 bits
    /// integer.
    ///
    /// @param in    The input of the PRP.
    /// @return      The evaluation of PRP(in).
    ///
    /// @exception std::runtime_error The Prp class is not available.
    ///
    uint64_t encrypt_64(const uint64_t in);

    ///
    /// @brief PRP inversion
    ///
    /// Inverts the pseudo random permutation on the input string.
    ///
    /// @param in    The input for the PRP inversion.
    /// @param out   The evaluation of PRP^{-1}(in).
    ///
    /// @exception std::runtime_error The Prp class is not available.
    ///
    void decrypt(const std::string& in, std::string& out);

    ///
    /// @brief PRP inversion
    ///
    /// Inverts the pseudo random permutation on the input string.
    ///
    /// @param in   The input for the PRP inversion.
    /// @return     The evaluation of PRP^{-1}(in).
    ///
    /// @exception std::runtime_error The Prp class is not available.
    ///
    std::string decrypt(const std::string& in);


    ///
    /// @brief PRP inversion
    ///
    /// Inverts the pseudo random permutation on the input buffer.
    ///
    /// @param in   The input for the PRP inversion.
    /// @param len          The length of the in buffer.
    /// @param[out] out     The output of the PRP inversion.
    ///
    /// @exception std::runtime_error The Prp class is not available.
    ///
    void decrypt(const uint8_t* in, const unsigned int len, uint8_t* out);

    ///
    /// @brief PRP inversion
    ///
    /// Inverts the pseudo random permutation on the input 32 bits integer.
    ///
    /// @param in   The input for the PRP inversion.
    /// @return     The evaluation of PRP^{-1}(in).
    ///
    /// @exception std::runtime_error The Prp class is not available.
    ///
    uint32_t decrypt(const uint32_t in);
    ///
    /// @brief PRP inversion
    ///
    /// Inverts the pseudo random permutation on the input 64 bits integer.
    ///
    /// @param in   The input for the PRP inversion.
    /// @return     The evaluation of PRP^{-1}(in).
    ///
    /// @exception std::runtime_error The Prp class is not available.
    ///
    uint64_t decrypt_64(const uint64_t in);

    // Again, avoid any assignement of Cipher objects
    Prp& operator=(const Prp& h) = delete;
    Prp& operator=(Prp& h) = delete;

private:
    static constexpr uint8_t kContextSize = 112;

    Key<kContextSize> aez_ctx_;

    explicit Prp(Key<kContextSize>&& context);

    static Key<kContextSize> init_random_aez_ctx();
    static Key<kContextSize> init_aez_ctx(Key<kKeySize>&& k);

    ///
    /// @brief Initialize the availability flag.
    ///
    /// Calls libsodium to determine if the aesni feature or the neon
    /// features are enabled on the host CPU. This function **must** be
    /// called before any use of the Prp class. Otherwise, the availability
    /// flag is set to false by default.
    ///
    ///
    static void compute_is_available() noexcept;

    /// @brief  Returns the size (in bytes) of the serialized representation of
    ///         the object
    ///
    /// @return The size in bytes of the buffer needed to serialize the object.
    ///
    size_t serialized_size() const noexcept
    {
        return kContextSize;
    }

    /// @brief Serialize the object in the given buffer
    ///
    /// @param[out] out The serialization buffer. It must be
    ///                 at least kSerializedSize bytes large.

    ///
    void serialize(uint8_t* out) const;

    /// @brief Deserialize a buffer into a Prg object
    ///
    /// This static function constructs a new Prg object out of the binary
    /// representation of the input buffer in. The in buffer must be at least
    /// kSerializedSize bytes large.
    ///
    /// @param  in      The byte buffer containing the binary representation of
    ///                 the Prp object.
    /// @param  in_size The size of the in buffer.
    /// @param  n_bytes_read    The number of bytes from in read during the
    ///                         deserialization
    ///
    /// @exception  std::invalid_argument   The size of the in buffer (in_size)
    ///                                     is smaller than kContextSize.
    static Prp deserialize(uint8_t*     in,
                           const size_t in_size,
                           size_t&      n_bytes_read);

    static bool is_available__;
};


} // namespace crypto
} // namespace sse
