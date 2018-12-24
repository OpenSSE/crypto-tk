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

template<uint16_t NBYTES>
class ConstrainedRCPrfElement;

class RCPrfBase
{
    // TODO: put the tree height in RCPrfBase
public:
    static constexpr uint8_t kKeySize    = 32;
    using depth_type                     = uint8_t;
    static constexpr uint8_t  kMaxHeight = 8 * sizeof(depth_type);
    static constexpr uint64_t kMaxLeaves = 1UL << (kMaxHeight - 1);

    static inline uint64_t leaf_count(const depth_type height)
    {
        if (height == 0) {
            return 0;
        }
        if (height >= 65) {
            return ~0;
        }
        return (1UL << (height - 1));
    }

protected:
    enum RCPrfTreeNodeChild : uint8_t
    {
        LeftChild  = 0,
        RightChild = 1
    };

    static inline RCPrfTreeNodeChild get_child(depth_type tree_height,
                                               uint64_t   leaf,
                                               depth_type node_depth)
    {
        // the -2 term comes from two facts:
        // - the minimum valid tree height is 1 (single note)
        // - the maximum depth of a node is tree_height-1
        uint64_t mask = 1UL << (tree_height - node_depth - 2);

        return ((leaf & mask) == 0) ? LeftChild : RightChild;
    }

    template<uint16_t NBYTES>
    static std::array<uint8_t, NBYTES> derive_leaf(const Prg& base_prg,
                                                   depth_type tree_height,
                                                   depth_type base_depth,
                                                   uint64_t   leaf)
    {
        assert(tree_height > base_depth + 1);
        // std::cerr << "Leaf " << leaf << std::endl;

        if (tree_height == base_depth + 2) {
            // only one derivation to do
            RCPrfTreeNodeChild child = get_child(tree_height, leaf, base_depth);
            std::array<uint8_t, NBYTES> result;

            // finish by evaluating the leaf
            base_prg.derive(
                static_cast<uint32_t>(child) * NBYTES, NBYTES, result.data());

            return result;
        }

        assert(tree_height - base_depth > 2);
        // the first step is done from the base PRG
        RCPrfTreeNodeChild child = get_child(tree_height, leaf, base_depth);
        Key<kKeySize>      subkey
            = base_prg.derive_key<kKeySize>(static_cast<uint16_t>(child));
        // std::cerr << (int)child << std::endl;
        // now proceed with the subkeys until we reach the leaf's parent
        for (uint8_t i = base_depth + 1; i < tree_height - 2; i++) {
            child = get_child(tree_height, leaf, i);
            // std::cerr << (int)child << std::endl;
            subkey = Prg::derive_key<kKeySize>(std::move(subkey),
                                               static_cast<uint16_t>(child));
        }

        std::array<uint8_t, NBYTES> result;

        // finish by evaluating the leaf
        child = get_child(tree_height, leaf, tree_height - 2);
        // std::cerr << (int)child << std::endl;

        Prg::derive(std::move(subkey),
                    static_cast<uint32_t>(child) * NBYTES,
                    NBYTES,
                    result.data());

        return result;
    }

    template<uint16_t NBYTES>
    static void generate_constrained_subkeys(
        const Prg&       base_prg,
        const depth_type tree_height,
        const depth_type subtree_height,
        const uint64_t   subtree_min,
        const uint64_t   subtree_max,
        const uint64_t   min,
        const uint64_t   max,
        std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>&
            constrained_elements);

    template<uint16_t NBYTES>
    static void generate_leaf(
        const Prg&       base_prg,
        const depth_type tree_height,
        const depth_type subtree_height,
        const uint64_t   subtree_min,
        const uint64_t   subtree_max,
        const uint64_t   min,
        const uint64_t   max,
        std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>&
            constrained_elements);
};

template<uint16_t NBYTES>
class ConstrainedRCPrfElement : public RCPrfBase
{
public:
    ConstrainedRCPrfElement(depth_type height,
                            depth_type subtree_height,
                            uint64_t   min,
                            uint64_t   max)
        : tree_height_(height), subtree_height_(subtree_height), min_leaf_(min),
          max_leaf_(max)
    {
        if (subtree_height == 0) {
            throw std::invalid_argument("Subtree height should be strictly "
                                        "larger than 0.");
        }
        if (subtree_height >= height) {
            throw std::invalid_argument(
                "Subtree height is not smaller than the tree height");
        }
        if (max < min) {
            throw std::invalid_argument(
                "Invalid range: max is larger than min: max="
                + std::to_string(max) + ", min=" + std::to_string(min));
        }
        // uint64_t n_leaves = (sub)
        if ((max - min + 1) != RCPrfBase::leaf_count(subtree_height_)) {
            throw std::invalid_argument(
                "Invalid range: the range's width "
                "should be 2^(subtree_height - 1): range's width="
                + std::to_string(max - min + 1) + "(max=" + std::to_string(max)
                + ", min=" + std::to_string(min) + "), expected width = "
                + std::to_string(RCPrfBase::leaf_count(subtree_height_)));
        }
    }

public:
    uint64_t min_leaf() const
    {
        return min_leaf_;
    }
    uint64_t max_leaf() const
    {
        return max_leaf_;
    }

    virtual std::array<uint8_t, NBYTES> eval(uint64_t leaf) const = 0;

protected:
    const depth_type tree_height_;
    const depth_type subtree_height_;
    const uint64_t   min_leaf_;
    const uint64_t   max_leaf_;
};


template<uint16_t NBYTES>
class ConstrainedRCPrfInnerElement : public ConstrainedRCPrfElement<NBYTES>
{
public:
    ConstrainedRCPrfInnerElement(Key<RCPrfBase::kKeySize>&& key,
                                 RCPrfBase::depth_type      height,
                                 RCPrfBase::depth_type      subtree_height,
                                 uint64_t                   min,
                                 uint64_t                   max)
        : ConstrainedRCPrfElement<NBYTES>(height, subtree_height, min, max),
          base_prg_(std::move(key))
    {
        if (subtree_height <= 1) {
            throw std::invalid_argument("Subtree height should be strictly "
                                        "larger than 1 for an inner element.");
        }
    }

    ConstrainedRCPrfInnerElement(const ConstrainedRCPrfInnerElement& cprf)
        = delete;
    ConstrainedRCPrfInnerElement& operator=(
        const ConstrainedRCPrfInnerElement& cprf)
        = delete;

    ConstrainedRCPrfInnerElement(ConstrainedRCPrfInnerElement&& cprf)
        : ConstrainedRCPrfElement<NBYTES>(cprf.tree_height_,
                                          cprf.subtree_height_,
                                          cprf.min_leaf_,
                                          cprf.max_leaf_),
          base_prg_(std::move(cprf.base_prg_))
    {
    }

    std::array<uint8_t, NBYTES> eval(uint64_t leaf) const override;

private:
    Prg base_prg_;
};

template<uint16_t NBYTES>
std::array<uint8_t, NBYTES> ConstrainedRCPrfInnerElement<NBYTES>::eval(
    uint64_t leaf) const
{
    if (leaf < this->min_leaf_) {
        std::out_of_range(
            "Leaf index is less than the range's minimum: leaf index="
            + std::to_string(leaf)
            + ", range min=" + std::to_string(this->min_leaf_));
    }
    if (leaf > this->max_leaf_) {
        std::out_of_range(
            "Leaf index is bigger than the range's maximum: leaf index="
            + std::to_string(leaf)
            + ", range max=" + std::to_string(this->max_leaf_));
    }

    uint8_t base_depth = this->tree_height_ - this->subtree_height_;
    return RCPrfBase::derive_leaf<NBYTES>(
        base_prg_, this->tree_height_, base_depth, leaf);
}

template<uint16_t NBYTES>
class ConstrainedRCPrfLeafElement : public ConstrainedRCPrfElement<NBYTES>
{
public:
    ConstrainedRCPrfLeafElement(std::array<uint8_t, NBYTES> buffer,
                                RCPrfBase::depth_type       height,
                                RCPrfBase::depth_type       subtree_height,
                                uint64_t                    min,
                                uint64_t                    max)
        : ConstrainedRCPrfElement<NBYTES>(height, subtree_height, min, max),
          leaf_buffer_(std::move(buffer))
    {
        if (subtree_height != 1) {
            throw std::invalid_argument(
                "Subtree height should be exactly 1 for a leaf element.");
        }
    }

    ConstrainedRCPrfLeafElement(const ConstrainedRCPrfLeafElement& cprf)
        = delete;
    ConstrainedRCPrfLeafElement& operator=(
        const ConstrainedRCPrfLeafElement& cprf)
        = delete;

    ConstrainedRCPrfLeafElement(ConstrainedRCPrfLeafElement&& cprf)
        : ConstrainedRCPrfElement<NBYTES>(cprf.tree_height_,
                                          cprf.subtree_height_,
                                          cprf.min_leaf_,
                                          cprf.max_leaf_),
          leaf_buffer_(std::move(cprf.leaf_buffer_))
    {
    }

    std::array<uint8_t, NBYTES> eval(uint64_t leaf) const override;

private:
    std::array<uint8_t, NBYTES> leaf_buffer_;
};

template<uint16_t NBYTES>
std::array<uint8_t, NBYTES> ConstrainedRCPrfLeafElement<NBYTES>::eval(
    uint64_t leaf) const
{
    if (leaf != this->min_leaf_) {
        throw std::out_of_range(
            "Invalid leaf value in 'eval': leaf(=" + std::to_string(leaf)
            + ") should be equal to min(=" + std::to_string(this->min_leaf_)
            + ")");
    }
    return leaf_buffer_;
}

template<uint16_t NBYTES>
class ConstrainedRCPrf : public RCPrfBase
{
public:
    ConstrainedRCPrf(
        uint64_t min,
        uint64_t max,
        std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>&&
            elements)
        : min_leaf_(min), max_leaf_(max), elements_(std::move(elements))
    {
    }

    ConstrainedRCPrf(const ConstrainedRCPrf& cprf) = delete;
    ConstrainedRCPrf& operator=(const ConstrainedRCPrf& cprf) = delete;

    ConstrainedRCPrf(ConstrainedRCPrf&& cprf)
        : min_leaf_(cprf.min_leaf_), max_leaf_(cprf.max_leaf_),
          elements_(std::move(cprf.elements_))
    {
    }


    std::array<uint8_t, NBYTES> eval(uint64_t leaf) const;

private:
    const uint64_t                                                min_leaf_;
    const uint64_t                                                max_leaf_;
    std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>> elements_;
};

template<uint16_t NBYTES>
std::array<uint8_t, NBYTES> ConstrainedRCPrf<NBYTES>::eval(uint64_t leaf) const
{
    for (const auto& elt : elements_) {
        if (elt->min_leaf() <= leaf && leaf <= elt->max_leaf()) {
            return elt->eval(leaf);
        }
    }
    throw std::invalid_argument("Leaf not in any element range");
}
template<uint16_t NBYTES>
void RCPrfBase::generate_leaf(
    const Prg&       base_prg,
    const depth_type tree_height,
    const depth_type subtree_height,
    const uint64_t   subtree_min,
    const uint64_t   subtree_max,
    const uint64_t   min,
    const uint64_t   max,
    std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>&
        constrained_elements)
{
    RCPrfTreeNodeChild child = (min == subtree_min) ? LeftChild : RightChild;
    std::array<uint8_t, NBYTES> buffer;

    base_prg.derive(
        static_cast<uint32_t>(child) * NBYTES, NBYTES, buffer.data());


    std::unique_ptr<ConstrainedRCPrfLeafElement<NBYTES>> elt(
        new ConstrainedRCPrfLeafElement<NBYTES>(
            std::move(buffer), tree_height, subtree_height - 1, min, max));
    constrained_elements.emplace_back(std::move(elt));
}

template<uint16_t NBYTES>
void RCPrfBase::generate_constrained_subkeys(
    const Prg&       base_prg,
    const depth_type tree_height,
    const depth_type subtree_height,
    const uint64_t   subtree_min,
    const uint64_t   subtree_max,
    const uint64_t   min,
    const uint64_t   max,
    std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>&
        constrained_elements)
{
    if (subtree_height <= 2) {
        // we are in a 'special' case, that we want to separate to simplify the
        // code. Essentially, we know that, if we are in this case, there is a
        // single leaf to generate

        assert(min == max);
        RCPrfBase::generate_leaf(base_prg,
                                 tree_height,
                                 subtree_height,
                                 subtree_min,
                                 subtree_max,
                                 min,
                                 max,
                                 constrained_elements);
        return;
    }

    uint64_t subtree_mid = (subtree_max + subtree_min) / 2;

    if (min <= subtree_mid) {
        // the selected range spans on the left subtree
        Key<kKeySize> subkey
            = base_prg.derive_key<kKeySize>(static_cast<uint16_t>(LeftChild));

        if ((min == subtree_min) && (max >= subtree_mid)) {
            // if the subkey spans exactly the searched range, put it in the
            // result vector and stop here


            std::unique_ptr<ConstrainedRCPrfInnerElement<NBYTES>> elt(
                new ConstrainedRCPrfInnerElement<NBYTES>(std::move(subkey),
                                                         tree_height,
                                                         subtree_height - 1,
                                                         subtree_min,
                                                         subtree_mid));
            constrained_elements.emplace_back(std::move(elt));
        } else {
            // otherwise, recurse on the left subtree
            // take care that the selected span for the left subtree can be
            // [min, subtree_mid] if max > subtree_mid (i.e. the range spans on
            // both subtrees)
            RCPrfBase::generate_constrained_subkeys(Prg(std::move(subkey)),
                                                    tree_height,
                                                    subtree_height - 1,
                                                    subtree_min,
                                                    subtree_mid,
                                                    min,
                                                    std::min(max, subtree_mid),
                                                    constrained_elements);
        }
    }

    if (max > subtree_mid) {
        // the selected range spans on the right subtree
        Key<kKeySize> subkey
            = base_prg.derive_key<kKeySize>(static_cast<uint16_t>(RightChild));
        if ((min <= subtree_mid + 1) && (max == subtree_max)) {
            // if the subkey spans exactly the searched range, put it in the
            // result
            // vector and stop here

            std::unique_ptr<ConstrainedRCPrfInnerElement<NBYTES>> elt(
                new ConstrainedRCPrfInnerElement<NBYTES>(std::move(subkey),
                                                         tree_height,
                                                         subtree_height - 1,
                                                         subtree_mid + 1,
                                                         subtree_max));
            constrained_elements.emplace_back(std::move(elt));
        } else {
            // again, be careful with the min value of the selected range of the
            // recursive call
            RCPrfBase::generate_constrained_subkeys(
                Prg(std::move(subkey)),
                tree_height,
                subtree_height - 1,
                subtree_mid + 1,
                subtree_max,
                std::max(min, subtree_mid + 1),
                max,
                constrained_elements);
        }
    }
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
class RCPrf : public RCPrfBase
{
public:
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

    ConstrainedRCPrf<NBYTES> constrain(uint64_t min, uint64_t max) const;

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

    return RCPrfBase::derive_leaf<NBYTES>(root_prg_, tree_height_, 0, leaf);
}
template<uint16_t NBYTES>
ConstrainedRCPrf<NBYTES> RCPrf<NBYTES>::constrain(uint64_t min,
                                                  uint64_t max) const
{
    // TODO: check bounds
    // uint64_t max_range
    // = (tree_height_ == 64) ? ~0 : ((1UL << tree_height_) - 1);
    uint64_t max_range = RCPrfBase::leaf_count(tree_height_) - 1;
    std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>
        constrained_elements;
    RCPrfBase::generate_constrained_subkeys(root_prg_,
                                            tree_height_,
                                            tree_height_,
                                            0,
                                            max_range,
                                            min,
                                            max,
                                            constrained_elements);

    return ConstrainedRCPrf<NBYTES>(min, max, std::move(constrained_elements));
}

} // namespace crypto
} // namespace sse