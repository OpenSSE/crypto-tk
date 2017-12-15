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


#include "prf.hpp"


// Explicitely instantiate some templates for the code coverage
#ifdef CHECK_TEMPLATE_INSTANTIATION
namespace sse {
namespace crypto {
template class Prf<1>;
template std::array<uint8_t, 1> Prf<1>::prf(
    const std::array<uint8_t, 20>& in) const;
template Key<1> Prf<1>::derive_key(const std::array<uint8_t, 20>& in) const;

template class Prf<10>;
template std::array<uint8_t, 10> Prf<10>::prf(
    const std::array<uint8_t, 40>& in) const;
template Key<10> Prf<10>::derive_key(const std::array<uint8_t, 40>& in) const;

template class Prf<20>;
template std::array<uint8_t, 20> Prf<20>::prf(
    const std::array<uint8_t, 50>& in) const;
template Key<20> Prf<20>::derive_key(const std::array<uint8_t, 50>& in) const;

template class Prf<128>;
template std::array<uint8_t, 128> Prf<128>::prf(
    const std::array<uint8_t, 100>& in) const;
template Key<128> Prf<128>::derive_key(
    const std::array<uint8_t, 100>& in) const;

template class Prf<1024>;
template std::array<uint8_t, 1024> Prf<1024>::prf(
    const std::array<uint8_t, 200>& in) const;
template Key<1024> Prf<1024>::derive_key(
    const std::array<uint8_t, 200>& in) const;

template class Prf<2000>;
} // namespace crypto
} // namespace sse
#endif
