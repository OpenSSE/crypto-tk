//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015-2016 Raphael Bost
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

#include <cstdint>

#include <array>
#include <string>


namespace sse
{
    namespace crypto
    {
        
        /*****
         * Prg class
         *
         * Opaque class for a pseudo random generator.
         *
         * It is constructed with a blockcipher in CTR mode.
         ******/
        
        class Prg
        {
        public:
            static constexpr uint8_t kKeySize = 32;
            
            Prg() = delete;
            Prg(const std::array<uint8_t,kKeySize>& k);
            Prg(const uint8_t* k);

            // we should not be able to duplicate Cipher objects
            Prg(const Prg& c) = delete;
            Prg(Prg& c) = delete;
            Prg(const Prg&& c) = delete;
            Prg(Prg&& c) = delete;
            
                        
            ~Prg();
            
            void derive(const size_t len, std::string &out) const;
            std::string derive(const size_t len) const;

            void derive(const uint32_t offset, const size_t len, std::string &out) const;
            std::string derive(const uint32_t offset, const size_t len) const;

            // Again, avoid any assignement of Cipher objects
            Prg& operator=(const Prg& h) = delete;
            Prg& operator=(Prg& h) = delete;
            
        private:	
            class PrgImpl; // not defined in the header
            PrgImpl *prg_imp_; // opaque pointer
        };

        
    }
}