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

#include <algorithm>
#include <exception>
#include <iostream>
#include <memory>
#include <vector>

namespace sse {
namespace crypto {

template<uint16_t NBYTES>
class ConstrainedRCPrfElement;
template<uint16_t NBYTES>
class ConstrainedRCPrf;

///
/// @class RCPrfParams
///
/// @brief  Class encapsulating all the parameters and types necessary to the
///         Range-Constrained PRF implementation.
///
/// The RCPrfParams class defines the types, constants and (very) generic
/// functions necessary to the Range-Constrained PRF tree-based implementation.
/// It is not meant to be instantiated.

///
struct RCPrfParams
{
    /// @brief Type used for the tree depth.
    using depth_type = uint8_t;

    /// @brief Size (in bytes) of a RC-PRF key
    static constexpr uint8_t kKeySize = 32;
    /// @brief Maximum height supported by the tree construction.
    static constexpr depth_type kMaxHeight = 8 * sizeof(depth_type);
    /// @brief  Maximum number of leaves (i.e. the size of the message space)
    ///         supported by the construction.
    static constexpr uint64_t kMaxLeaves = (1UL << (kMaxHeight - 1));

    /// @brief Returns the number of leaves supported by a tree of the given
    /// height
    ///
    /// @param height The height of the tree
    ///
    static constexpr uint64_t leaf_count_generic(const depth_type height)
    {
        return (1UL << (height - 1));
    }

    /// @brief Returns the practical number of leaves supported by a tree of the
    /// given height. The height is limited to 65, i.e. the construction cannot
    /// support more than 2^64 leaves.
    ///
    /// @param height The height of the tree.
    ///
    static inline uint64_t leaf_count(const depth_type height)
    {
        if (height == 0) {
            return 0;
        }
        if (height >= 65) {
            return ~0;
        }
        return leaf_count_generic(height);
    }


    inline static constexpr bool ranges_intersect(uint64_t min_1,
                                                  uint64_t max_1,
                                                  uint64_t min_2,
                                                  uint64_t max_2)
    {
        return (min_1 <= max_2) && (min_2 <= max_1);
    }
    /// @brief Type encoding a choice of child in a binary tree.
    enum RCPrfTreeNodeChild : uint8_t
    {
        LeftChild  = 0,
        RightChild = 1
    };
};

static_assert(RCPrfParams::kMaxLeaves
                  == RCPrfParams::leaf_count_generic(RCPrfParams::kMaxHeight),
              "Computation of the maximum number of leaves is not consistent");


///
/// @class RCPrfBase
/// @brief Base class for the Range-Constrained PRF implementation.
///
/// @tparam NBYTES     The size in bytes of the generated leaves values.
///
/// The RCPrfBase class implements the common tree algorithms used in the RC-PRF
/// implementation. It is not meant to be instantiated.
///
template<uint16_t NBYTES>
class RCPrfBase : public RCPrfParams
{
public:
    RCPrfBase() = delete;
    ///
    /// @brief Constructor
    ///
    /// Constructs a RCPrfBase object representing a tree of the given height
    ///
    /// @param height   The height of the tree to construct. A single node tree
    ///                 (i.e. a tree consisting only in a leaf) has height 1.
    ///
    explicit RCPrfBase(const depth_type height) noexcept : tree_height_(height)
    {
    }

    /* LCOV_EXCL_START */
    ///
    /// @brief Copy constructor
    ///
    RCPrfBase(const RCPrfBase& rcprf) = default;

    ///
    /// @brief Move constructor
    ///
    RCPrfBase(RCPrfBase&& rcprf) noexcept = default;
    /* LCOV_EXCL_STOP */

    ///
    /// @brief Return the height of the represented tree
    ///
    inline depth_type tree_height() const
    {
        return tree_height_;
    }

protected:
    ///
    /// @brief Compute the direction of the root-to-leaf path at a given depth
    ///
    /// When following the root-to-leaf path, return which of the left of the
    /// right child of the node at the given depth we have to take next.
    ///
    /// @param leaf         The leaf to go to from the tree's root
    /// @param node_depth   The depth of the node on the root-to-leaf path (a 0
    ///                     node-depth points to the root, a tree_height-1 depth
    ///                     is the leaf).
    ///
    /// @return             The child to go to in the root-to-leaf path.
    ///
    inline RCPrfTreeNodeChild get_child(uint64_t   leaf,
                                        depth_type node_depth) const
    {
        // the -2 term comes from two facts:
        // - the minimum valid tree height is 1 (single note)
        // - the maximum depth of a node is tree_height-1
        uint64_t mask = 1UL << (tree_height() - node_depth - 2);

        return ((leaf & mask) == 0) ? LeftChild : RightChild;
    }

    ///
    /// @brief Derive a leaf from an inner node
    ///
    /// Derive a leaf from an inner node represented by a Prg object. This Prg
    /// uses the content of the node as its key.
    ///
    /// @param base_prg    The Prg object representing the node and using the
    ///                    node's content as its key.
    /// @param base_depth  The depth of the starting node (a 0
    ///                    depth points to the root, a tree_height-1 depth
    ///                    corresponds to a leaf).
    /// @param leaf        The leaf to derive.
    ///
    /// @return An NBYTES buffer with the leaf's value.
    std::array<uint8_t, NBYTES> derive_leaf(const Prg& base_prg,
                                            depth_type base_depth,
                                            uint64_t   leaf) const;


    ///
    /// @brief Generate the constrained key necessary to derive the tree's
    ///        leaves in the specified range.
    ///
    /// Computes the nodes necessary to derive all the leaves in the given
    /// range. The starting node is the root of the (sub)tree represented by the
    /// object.
    ///
    /// @param min             The minimum value of the leaves index being able
    ///                        to be generated from the output of the algorithm.
    /// @param max             The maximum value of the leaves index being able
    ///                        to be generated from the output of the algorithm.
    ///
    /// @param[out] constrained_elements   The vector of nodes necessary to
    ///                                    generate the leaves with index
    ///                                    between min and max
    ///
    virtual void generate_constrained_subkeys(
        const uint64_t min,
        const uint64_t max,
        std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>&
            constrained_elements) const = 0;

    ///
    /// @brief Generate the constrained key necessary to derive the tree's
    ///        leaves in the specified range.
    ///
    /// Computes the nodes necessary to derive all the leaves in the given
    /// range. The starting node is not necessary the root of the tree and is
    /// represented by the base_prg object.
    ///
    /// @param base_prg        The Prg object representing the node to start the
    ///                        generation from. Must not necessary be the root.
    /// @param tree_height     The height of the tree.
    /// @param subtree_height  The height of the base node rooted subtree. A
    ///                        height of tree_height represents the entire tree,
    /// @param subtree_min     The minimum leaf index supported by the subtree
    ///                        rooted at the base node.
    /// @param subtree_max     The maximum leaf index supported by the subtree
    ///                        rooted at the base node.
    /// @param min             The minimum value of the leaves index being able
    ///                        to be generated from the output of the algorithm.
    /// @param max             The maximum value of the leaves index being able
    ///                        to be generated from the output of the algorithm.
    ///
    /// @param[out] constrained_elements   The vector of nodes necessary to
    ///                                    generate the leaves with index
    ///                                    between min and max
    ///
    static void generate_constrained_subkeys_from_node(
        const Prg&       base_prg,
        const depth_type tree_height,
        const depth_type subtree_height,
        const uint64_t   subtree_min,
        const uint64_t   subtree_max,
        const uint64_t   min,
        const uint64_t   max,
        std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>&
            constrained_elements);

    ///
    /// @brief Generate a leaf from its parent node.
    ///
    /// Computes the leaf given as input from its parent node, represented by
    /// the base_prg object. This function is a specialization of the
    /// generate_constrained_subkeys_from_node function for height 2 subtrees.
    ///
    /// @param base_prg        The Prg object representing the parent node of
    ///                        the leaf to generate.
    /// @param tree_height     The height of the tree.
    /// @param subtree_min     The minimum leaf index supported by the subtree
    ///                        (of height two) rooted at the base node. The
    ///                        subtree's maximum leaf index does not have to be
    ///                        specified: we know it is subtree_min+1.
    /// @param leaf            The index of the leaf to generate.
    ///
    /// @param[out] constrained_elements   The vector of nodes in which the leaf
    ///                                    to generate will be put.
    ///
    static void generate_leaf_from_parent(
        const Prg&       base_prg,
        const depth_type tree_height,
        const uint64_t   subtree_min,
        const uint64_t   leaf,
        std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>&
            constrained_elements);

private:
    const depth_type tree_height_;
};


template<uint16_t NBYTES>
std::array<uint8_t, NBYTES> RCPrfBase<NBYTES>::derive_leaf(
    const Prg& base_prg,
    depth_type base_depth,
    uint64_t   leaf) const
{
    assert(this->tree_height() > base_depth + 1);

    if (this->tree_height() == base_depth + 2) {
        // only one derivation to do
        RCPrfTreeNodeChild          child = get_child(leaf, base_depth);
        std::array<uint8_t, NBYTES> result;

        // finish by evaluating the leaf
        base_prg.derive(
            static_cast<uint32_t>(child) * NBYTES, NBYTES, result.data());

        return result;
    }

    assert(this->tree_height() - base_depth > 2);
    // the first step is done from the base PRG
    RCPrfTreeNodeChild child = get_child(leaf, base_depth);
    Key<kKeySize>      subkey
        = base_prg.derive_key<kKeySize>(static_cast<uint16_t>(child));
    // now proceed with the subkeys until we reach the leaf's parent
    for (uint8_t i = base_depth + 1; i < this->tree_height() - 2; i++) {
        child  = get_child(leaf, i);
        subkey = Prg::derive_key<kKeySize>(std::move(subkey),
                                           static_cast<uint16_t>(child));
    }

    std::array<uint8_t, NBYTES> result;

    // finish by evaluating the leaf
    child = get_child(leaf, tree_height() - 2);

    Prg::derive(std::move(subkey),
                static_cast<uint32_t>(child) * NBYTES,
                NBYTES,
                result.data());

    return result;
}


///
/// @class ConstrainedRCPrfElement
/// @brief Abstract class representing RC-PRF constrained keys elements, i.e.
/// nodes of the tree.
///
/// @tparam NBYTES     The size in bytes of the generated leaf value.
///
/// The ConstrainedRCPrfElement class implements bounds checking during
/// construction and declares an evaluation function that has to be overridden
/// by subclasses.
///
template<uint16_t NBYTES>
class ConstrainedRCPrfElement : public RCPrfBase<NBYTES>
{
    friend class ConstrainedRCPrf<NBYTES>;

public:
    ///
    /// @brief Constructor
    ///
    /// Creates a ConstrainedRCPrfElement representing a subtree of given
    /// height and spanning over the specified leaves range.
    ///
    /// @param tree_height     The height of the tree.
    /// @param subtree_height  The height of the subtree represented by the
    ///                        element.
    /// @param min             The minimum leaf index spanned by the
    /// subtree.
    /// @param max             The maximum leaf index spanned by the
    /// subtree.
    ///
    /// @exception std::invalid_argument       The input subtree height is
    /// 0.
    /// @exception std::invalid_argument       The input subtree height is
    ///                                        larger than the tree height.
    /// @exception std::invalid_argument       The maximum leaf index is
    ///                                        strictly smaller than the
    ///                                        minimum leaf index.
    ///
    ConstrainedRCPrfElement(RCPrfParams::depth_type height,
                            RCPrfParams::depth_type subtree_height,
                            uint64_t                min,
                            uint64_t                max)
        : RCPrfBase<NBYTES>(height), subtree_height_(subtree_height),
          min_leaf_(min), max_leaf_(max)
    {
        if (subtree_height == 0) {
            /* LCOV_EXCL_START */
            // already covered by the subclasses
            throw std::invalid_argument("Subtree height should be strictly "
                                        "larger than 0.");
            /* LCOV_EXCL_STOP */
        }
        if (subtree_height >= this->tree_height()) {
            throw std::invalid_argument(
                "Subtree height is not smaller than the tree height");
        }
        if (max < min) {
            throw std::invalid_argument(
                "Invalid range: min is larger than max: max="
                + std::to_string(max) + ", min=" + std::to_string(min));
        }
        if ((max - min + 1)
            != RCPrfParams::leaf_count(this->subtree_height())) {
            throw std::invalid_argument(
                "Invalid range: the range's width "
                "should be 2^(subtree_height - 1): range's width="
                + std::to_string(max - min + 1) + "(max=" + std::to_string(max)
                + ", min=" + std::to_string(min) + "), expected width = "
                + std::to_string(
                      RCPrfParams::leaf_count(this->subtree_height())));
        }
    }

    virtual ~ConstrainedRCPrfElement() = default;

    /// @brief Returns the minimum leaf index supported by the element.
    uint64_t min_leaf() const
    {
        return min_leaf_;
    }

    /// @brief Returns the maximum leaf index supported by the element.
    uint64_t max_leaf() const
    {
        return max_leaf_;
    }

    /// @brief Returns the height of the subtree represented by the element
    RCPrfParams::depth_type subtree_height() const
    {
        return subtree_height_;
    }

    ///
    /// @brief Evaluate the Range-Constrained PRF
    ///
    /// Returns the value of the specified leaf computed from the
    /// constrained key element.
    ///
    /// @param leaf The index of the leaf to evaluate.
    ///
    /// @return A buffer containing the value of the leaf.
    ///
    virtual std::array<uint8_t, NBYTES> eval(uint64_t leaf) const = 0;


private:
    const RCPrfParams::depth_type subtree_height_;
    const uint64_t                min_leaf_;
    const uint64_t                max_leaf_;
};

///
/// @class ConstrainedRCPrfInnerElement
/// @brief Class representing a constrained key element that is an inner node of
/// the evaluation tree (i.e. not a leaf).
///
/// @tparam NBYTES     The size in bytes of the generated leaf value.
///
template<uint16_t NBYTES>
class ConstrainedRCPrfInnerElement : public ConstrainedRCPrfElement<NBYTES>
{
public:
    ///
    /// @brief Constructor
    ///
    /// Creates a ConstrainedRCPrfInnerElement representing a subtree of given
    /// height and spanning over the specified leaves range.
    ///
    /// @param key             The value of the subtree's node. The key given as
    ///                        input is moved, and is invalidated.
    /// @param subtree_height  The height of the subtree represented by the
    ///                        element.
    /// @param min             The minimum leaf index spanned by the subtree.
    /// @param max             The maximum leaf index spanned by the subtree.
    ///
    /// @exception std::invalid_argument    The input subtree is smaller
    ///                                     than 1.
    /// @exception std::invalid_argument    An std::invalid_argument exception
    ///                                     can be thrown by the parent class'
    ///                                     (ConstrainedRCPrfElement)
    ///                                     constructor.
    ///
    ConstrainedRCPrfInnerElement(Key<RCPrfParams::kKeySize>&& key,
                                 RCPrfParams::depth_type      height,
                                 RCPrfParams::depth_type      subtree_height,
                                 uint64_t                     min,
                                 uint64_t                     max)
        : ConstrainedRCPrfElement<NBYTES>(height, subtree_height, min, max),
          base_prg_(std::move(key))
    {
        if (subtree_height <= 1) {
            throw std::invalid_argument("Subtree height should be strictly "
                                        "larger than 1 for an inner element.");
        }
    }

    ///
    /// @brief Constructor
    ///
    /// Creates a ConstrainedRCPrfInnerElement representing a subtree of given
    /// height and spanning over the specified leaves range.
    ///
    /// @param subtree_prg     The Prg representing the subtree's root. The Prg
    ///                        object is moved by the constructor, and is
    ///                        invalidated.
    /// @param subtree_height  The height of the subtree represented by the
    ///                        element.
    /// @param min             The minimum leaf index spanned by the subtree.
    /// @param max             The maximum leaf index spanned by the subtree.
    ///
    /// @exception std::invalid_argument    The input subtree is smaller
    ///                                     than 1.
    /// @exception std::invalid_argument    An std::invalid_argument exception
    ///                                     can be thrown by the parent class'
    ///                                     (ConstrainedRCPrfElement)
    ///                                     constructor.
    ///
    ConstrainedRCPrfInnerElement(Prg&&                   subtree_prg,
                                 RCPrfParams::depth_type height,
                                 RCPrfParams::depth_type subtree_height,
                                 uint64_t                min,
                                 uint64_t                max)
        : ConstrainedRCPrfElement<NBYTES>(height, subtree_height, min, max),
          base_prg_(std::move(subtree_prg))
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

    /* LCOV_EXCL_START */
    ///
    /// @brief Move constructor
    ///
    /// @param cprf The ConstrainedRCPrfInnerElement to be moved
    ///
    ConstrainedRCPrfInnerElement(ConstrainedRCPrfInnerElement&& cprf) noexcept
        : ConstrainedRCPrfElement<NBYTES>(
              std::forward<ConstrainedRCPrfElement<NBYTES>>(cprf)),
          base_prg_(std::move(cprf.base_prg_))
    {
    }
    /* LCOV_EXCL_STOP */

    ///
    /// @brief Destructor
    ///
    ~ConstrainedRCPrfInnerElement() override = default;

    // Already documented by the parent class
    std::array<uint8_t, NBYTES> eval(uint64_t leaf) const override;

    // Already documented by the parent class
    void generate_constrained_subkeys(
        const uint64_t min,
        const uint64_t max,
        std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>&
            constrained_elements) const override;

private:
    Prg base_prg_;
};

template<uint16_t NBYTES>
std::array<uint8_t, NBYTES> ConstrainedRCPrfInnerElement<NBYTES>::eval(
    uint64_t leaf) const
{
    if (leaf < this->min_leaf()) {
        throw std::out_of_range(
            "Leaf index is less than the range's minimum: leaf index="
            + std::to_string(leaf)
            + ", range min=" + std::to_string(this->min_leaf()));
    }
    if (leaf > this->max_leaf()) {
        throw std::out_of_range(
            "Leaf index is bigger than the range's maximum: leaf index="
            + std::to_string(leaf)
            + ", range max=" + std::to_string(this->max_leaf()));
    }

    uint8_t base_depth = this->tree_height() - this->subtree_height();

    // we use this trick to avoid compilation errors (at least on clang)
    return static_cast<const ConstrainedRCPrfInnerElement<NBYTES>*>(this)
        ->RCPrfBase<NBYTES>::derive_leaf(base_prg_, base_depth, leaf);
}

template<uint16_t NBYTES>
void ConstrainedRCPrfInnerElement<NBYTES>::generate_constrained_subkeys(
    const uint64_t min,
    const uint64_t max,
    std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>&
        constrained_elements) const
{
    if (min < this->min_leaf() || max > this->max_leaf()) {
        throw std::out_of_range("ConstrainedRCPrfInnerElement::generate_"
                                "constrained_subkeys: the input range ("
                                + std::to_string(min) + ", "
                                + std::to_string(max)
                                + ") is out of the subtree range: ("
                                + std::to_string(this->min_leaf()) + ", "
                                + std::to_string(this->max_leaf()) + ").");
    }
    // not a constrain (at least not on this node)
    if (min == this->min_leaf() && max == this->max_leaf()) {
        std::unique_ptr<ConstrainedRCPrfInnerElement<NBYTES>> elt(
            new ConstrainedRCPrfInnerElement<NBYTES>(
                std::move(base_prg_.duplicate()),
                this->tree_height(),
                this->subtree_height(),
                this->min_leaf(),
                this->max_leaf()));
        constrained_elements.push_back(std::move(elt));
        return;
    }

    // use a regular constrain
    RCPrfBase<NBYTES>::generate_constrained_subkeys_from_node(
        base_prg_,
        this->tree_height(),
        this->subtree_height(),
        this->min_leaf(),
        this->max_leaf(),
        min,
        max,
        constrained_elements);
}

///
/// @class ConstrainedRCPrfLeafElement
/// @brief Class representing a constrained key element that a leaf.
///
/// @tparam NBYTES     The size in bytes of the generated leaf value.
///
template<uint16_t NBYTES>
class ConstrainedRCPrfLeafElement : public ConstrainedRCPrfElement<NBYTES>
{
public:
    ///
    /// @brief Constructor
    ///
    /// Creates a ConstrainedRCPrfLeafElement representing a leaf.
    ///
    /// @param tree_height     The height of the tree.
    /// @param leaf            The index of the represented leaf.
    ///
    /// @exception std::invalid_argument    An std::invalid_argument
    /// exception
    ///                                     can be thrown by the parent
    ///                                     class' (ConstrainedRCPrfElement)
    ///                                     constructor.
    ///
    ConstrainedRCPrfLeafElement(std::array<uint8_t, NBYTES> buffer,
                                RCPrfParams::depth_type     height,
                                uint64_t                    leaf)
        : ConstrainedRCPrfElement<NBYTES>(height, 1, leaf, leaf),
          leaf_buffer_(std::move(buffer))
    {
    }

    ConstrainedRCPrfLeafElement(const ConstrainedRCPrfLeafElement& cprf)
        = delete;
    ConstrainedRCPrfLeafElement& operator=(
        const ConstrainedRCPrfLeafElement& cprf)
        = delete;

    /* LCOV_EXCL_START */
    ///
    /// @brief Move constructor
    ///
    /// @param cprf The ConstrainedRCPrfInnerElement to be moved
    ///
    ConstrainedRCPrfLeafElement(ConstrainedRCPrfLeafElement&& cprf) noexcept
        : ConstrainedRCPrfElement<NBYTES>(
              std::forward<ConstrainedRCPrfElement<NBYTES>>(cprf)),
          leaf_buffer_(std::move(cprf.leaf_buffer_))
    {
    }
    /* LCOV_EXCL_STOP */

    ///
    /// @brief Destructor
    ///
    ~ConstrainedRCPrfLeafElement() override = default;

    // Already documented by the superclass
    std::array<uint8_t, NBYTES> eval(uint64_t leaf) const override;

    // Already documented by the parent class
    void generate_constrained_subkeys(
        const uint64_t min,
        const uint64_t max,
        std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>&
            constrained_elements) const override;

private:
    std::array<uint8_t, NBYTES> leaf_buffer_;
};

template<uint16_t NBYTES>
std::array<uint8_t, NBYTES> ConstrainedRCPrfLeafElement<NBYTES>::eval(
    uint64_t leaf) const
{
    if (leaf != this->min_leaf()) {
        throw std::out_of_range(
            "Invalid leaf value in 'eval': leaf(=" + std::to_string(leaf)
            + ") should be equal to min(=" + std::to_string(this->min_leaf())
            + ")");
    }
    return leaf_buffer_;
}

template<uint16_t NBYTES>
void ConstrainedRCPrfLeafElement<NBYTES>::generate_constrained_subkeys(
    const uint64_t min,
    const uint64_t max,
    std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>&
        constrained_elements) const
{
    if (min != this->min_leaf() || max != this->min_leaf()) {
        throw std::out_of_range(
            "ConstrainedRCPrfLeafElement::constrain: the input range ("
            + std::to_string(min) + ", " + std::to_string(max)
            + ") is not reduced to the leaf index "
            + std::to_string(this->min_leaf()));
    }
    std::unique_ptr<ConstrainedRCPrfLeafElement<NBYTES>> elt(
        new ConstrainedRCPrfLeafElement<NBYTES>(
            leaf_buffer_, this->tree_height(), this->min_leaf()));
    constrained_elements.emplace_back(std::move(elt));
}

///
/// @class ConstrainedRCPrf
/// @brief Class representing a Range-Constrained PRF after having been
/// constrained to a specific range.
///
/// A ConstrainedRCPrf is a RCPrf object whose evaluation has been constrained
/// to a specific range. This is a cryptographic guarantee: it is not only
/// enforced by bounds checking, but also by a cryptographic proof that we
/// cannot evaluate the PRF on inputs outside of the specified range from the
/// return ConstrainedRCPrf object
///
/// @tparam NBYTES     The size in bytes of the generated leaf value.
///
template<uint16_t NBYTES>
class ConstrainedRCPrf : public RCPrfBase<NBYTES>
{
public:
    static RCPrfParams::depth_type get_element_height(
        const std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>&
            elements)
    {
        if (elements.empty()) {
            throw std::invalid_argument("Empty key elements vector");
        }
        RCPrfParams::depth_type h = elements[0]->tree_height();

        for (auto it = elements.begin() + 1; it != elements.end(); ++it) {
            if (h != (*it)->tree_height()) {
                throw std::invalid_argument(
                    "Inconsistent tree heights: all the elements do not have "
                    "the same tree height.");
            }
        }

        return h;
    }
    ///
    /// @brief Constructor
    ///
    /// Creates a ConstrainedRCPrf from a vector of key elements (i.e. a set
    /// of tree nodes).
    ///
    /// @param elements     The vector containing the key elements. The
    /// vector
    ///                     is moved, and thus invalidated by the
    ///                     constructor.
    ///
    /// @exception std::invalid_argument    The vector is empty.
    /// @exception std::invalid_argument    The elements in the vector do
    ///                                     not span over a single range, but at
    ///                                     least two: the spans of the
    ///                                     elements in the vector are not
    ///                                     consecutive.
    /// @exception std::invalid_argument    The elements in the vector do not
    ///                                     have the same tree height (and hence
    ///                                     cannot come from the same tree).
    ///
    explicit ConstrainedRCPrf(
        std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>&&
            elements)
        : RCPrfBase<NBYTES>(get_element_height(elements)),
          elements_(std::move(elements))
    {
        // sort the elements
        struct MinComparator
        {
            bool operator()(
                const std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>& elt_1,
                const std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>& elt_2)
            {
                return elt_1->min_leaf() < elt_2->min_leaf();
            }
        };
        std::sort(elements_.begin(), elements_.end(), MinComparator());

        // check that the elements are consecutive
        for (auto it = elements_.begin() + 1; it != elements_.end(); ++it) {
            if ((*(it - 1))->max_leaf() + 1 != (*it)->min_leaf()) {
                throw std::invalid_argument("Non consecutive elements");
            }
        }
    }

    ConstrainedRCPrf(const ConstrainedRCPrf& cprf) = delete;
    ConstrainedRCPrf& operator=(const ConstrainedRCPrf& cprf) = delete;

    /* LCOV_EXCL_START */
    ///
    /// @brief Move constructor
    ///
    /// @param cprf The ConstrainedRCPrfInnerElement to be moved
    ///
    ConstrainedRCPrf(ConstrainedRCPrf&& cprf) noexcept
        : RCPrfBase<NBYTES>(std::forward<RCPrfBase<NBYTES>>(cprf)),
          elements_(std::move(cprf.elements_))
    {
    }
    /* LCOV_EXCL_STOP */

    /// @brief Returns the minimum leaf index supported by the constrained
    /// RC-PRF.
    uint64_t min_leaf() const
    {
        return elements_[0]->min_leaf();
    }

    /// @brief Returns the maximum leaf index supported by the constrained
    /// RC-PRF.
    uint64_t max_leaf() const
    {
        return elements_[elements_.size() - 1]->max_leaf();
    }

    /// @brief Evaluate the RC-RPF.
    ///
    /// Evaluates the RC-PRF on the input, i.e. returns the value of the
    /// specified leaf
    ///
    /// @param leaf The index of the leaf to evaluate.
    ///
    /// @return An array containing the value of the leaf.
    ///
    /// @exception std::out_of_range    The input leaf is out of the constrained
    ///                                 range.
    /// @exception std::runtime_error   The object is an invalid state, that is
    ///                                 not expected at all. It must have been
    ///                                 corrupted.
    ///
    std::array<uint8_t, NBYTES> eval(uint64_t leaf) const;


    ///
    /// @brief Reconstrain the PRF to a range.
    ///
    /// Returns a ConstrainedRCPrf that can only evaluate the PRF on the input
    /// range. This is a cryptographic guarantee: it is not only enforced by
    /// bounds checking, but also by a cryptographic proof that we cannot
    /// evaluate the PRF on inputs outside of the specified range from the
    /// return ConstrainedRCPrf object.
    ///
    /// @param min  The minimum value of the range to which the RC-PRF will be
    ///             constrained.
    /// @param max  The maximum value of the range to which the RC-PRF will be
    ///             constrained.
    ///
    /// @return     A ConstrainedRCPrf able to evaluate the PRF on inputs
    ///             between min and max
    ///
    /// @exception std::invalid_argument       The maximum leaf index is
    ///                                        strictly smaller than the minimum
    ///                                        leaf index.
    /// @exception std::out_of_range           The input range is not contained
    ///                                        in the receiver's contrained
    ///                                        range.
    ///
    ConstrainedRCPrf<NBYTES> constrain(uint64_t min, uint64_t max) const;

    // Already documented by the parent class
    void generate_constrained_subkeys(
        const uint64_t min,
        const uint64_t max,
        std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>&
            constrained_elements) const override;

private:
    std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>> elements_;
};

template<uint16_t NBYTES>
std::array<uint8_t, NBYTES> ConstrainedRCPrf<NBYTES>::eval(uint64_t leaf) const
{
    if (leaf < min_leaf() || leaf > max_leaf()) {
        throw std::out_of_range(
            "ConstrainedRCPrf::eval: Leaf (=" + std::to_string(leaf)
            + ") out of constrained range (" + std::to_string(min_leaf()) + ", "
            + std::to_string(max_leaf()) + ")");
    }
    for (const auto& elt : elements_) {
        if (elt->min_leaf() <= leaf && leaf <= elt->max_leaf()) {
            return elt->eval(leaf);
        }
    }
    /* LCOV_EXCL_START */
    throw std::runtime_error("ConstrainedRCPrf::eval: invalid state");
    /* LCOV_EXCL_STOP */
}

template<uint16_t NBYTES>
void ConstrainedRCPrf<NBYTES>::generate_constrained_subkeys(
    const uint64_t min,
    const uint64_t max,
    std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>&
        constrained_elements) const
{
    if (min < this->min_leaf() || max > this->max_leaf()) {
        throw std::out_of_range(
            "ConstrainedRCPrf::generate_constrained_subkeys: the input range ("
            + std::to_string(min) + ", " + std::to_string(max)
            + ") is out of the subtree range: ("
            + std::to_string(this->min_leaf()) + ", "
            + std::to_string(this->max_leaf()) + ").");
    }

    for (const auto& elt : elements_) {
        uint64_t subrange_min = elt->min_leaf();
        uint64_t subrange_max = elt->max_leaf();

        if (RCPrfParams::ranges_intersect(
                subrange_min, subrange_max, min, max)) {
            subrange_min = std::max(min, elt->min_leaf());
            subrange_max = std::min(max, elt->max_leaf());
            elt->generate_constrained_subkeys(
                subrange_min, subrange_max, constrained_elements);
        }
    }
}

template<uint16_t NBYTES>
ConstrainedRCPrf<NBYTES> ConstrainedRCPrf<NBYTES>::constrain(uint64_t min,
                                                             uint64_t max) const
{
    std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>
        constrained_elements;
    generate_constrained_subkeys(min, max, constrained_elements);

    return ConstrainedRCPrf<NBYTES>(std::move(constrained_elements));
}

template<uint16_t NBYTES>
void RCPrfBase<NBYTES>::generate_leaf_from_parent(
    const Prg&       base_prg,
    const depth_type tree_height,
    const uint64_t   subtree_min,
    const uint64_t   leaf,
    std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>&
        constrained_elements)
{
    RCPrfTreeNodeChild child = (leaf == subtree_min) ? LeftChild : RightChild;
    std::array<uint8_t, NBYTES> buffer;

    base_prg.derive(
        static_cast<uint32_t>(child) * NBYTES, NBYTES, buffer.data());


    std::unique_ptr<ConstrainedRCPrfLeafElement<NBYTES>> elt(
        new ConstrainedRCPrfLeafElement<NBYTES>(
            std::move(buffer), tree_height, leaf));
    constrained_elements.emplace_back(std::move(elt));
}

template<uint16_t NBYTES>
void RCPrfBase<NBYTES>::generate_constrained_subkeys_from_node(
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
        RCPrfBase::generate_leaf_from_parent(
            base_prg, tree_height, subtree_min, min, constrained_elements);
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
            constrained_elements.push_back(std::move(elt));
        } else {
            // otherwise, recurse on the left subtree
            // take care that the selected span for the left subtree can be
            // [min, subtree_mid] if max > subtree_mid (i.e. the range spans on
            // both subtrees)
            RCPrfBase::generate_constrained_subkeys_from_node(
                Prg(std::move(subkey)),
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
            constrained_elements.push_back(std::move(elt));
        } else {
            // again, be careful with the min value of the selected range of the
            // recursive call
            RCPrfBase::generate_constrained_subkeys_from_node(
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
class RCPrf : public RCPrfBase<NBYTES>
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
    RCPrf(Key<RCPrfParams::kKeySize>&& key, RCPrfParams::depth_type height)
        : RCPrfBase<NBYTES>(height), root_prg_(std::move(key))
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

    ///
    /// @brief Constrain the PRF to a range.
    ///
    /// Returns a ConstrainedRCPrf that can only evaluate the PRF on the input
    /// range. This is a cryptographic guarantee: it is not only enforced by
    /// bounds checking, but also by a cryptographic proof that we cannot
    /// evaluate the PRF on inputs outside of the specified range from the
    /// return ConstrainedRCPrf object.
    ///
    /// @param min  The minimum value of the range to which the RC-PRF will be
    ///             constrained.
    /// @param max  The maximum value of the range to which the RC-PRF will be
    ///             constrained.
    ///
    /// @return     A ConstrainedRCPrf able to evaluate the PRF on inputs
    ///             between min and max
    ///
    /// @exception std::invalid_argument       The maximum leaf index is
    ///                                        strictly smaller than the minimum
    ///                                        leaf index.
    /// @exception std::out_of_range           The maximum leaf index is larger
    ///                                        than the maximum supported leaf
    ///                                        index.
    ///
    ConstrainedRCPrf<NBYTES> constrain(uint64_t min, uint64_t max) const;

    // Already commented in the superclass
    void generate_constrained_subkeys(
        const uint64_t min,
        const uint64_t max,
        std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>&
            constrained_elements) const override;

private:
    Prg root_prg_;
};

template<uint16_t NBYTES>
std::array<uint8_t, NBYTES> RCPrf<NBYTES>::eval(uint64_t leaf) const
{
    if (leaf >> this->tree_height() != 0) {
        throw std::out_of_range("Invalid node index: leaf > 2^height -1.");
    }

    return static_cast<const RCPrf<NBYTES>*>(this)
        ->RCPrfBase<NBYTES>::derive_leaf(root_prg_, 0, leaf);
}

template<uint16_t NBYTES>
ConstrainedRCPrf<NBYTES> RCPrf<NBYTES>::constrain(uint64_t min,
                                                  uint64_t max) const
{
    std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>
        constrained_elements;
    generate_constrained_subkeys(min, max, constrained_elements);

    return ConstrainedRCPrf<NBYTES>(std::move(constrained_elements));
}

template<uint16_t NBYTES>
void RCPrf<NBYTES>::generate_constrained_subkeys(
    const uint64_t min,
    const uint64_t max,
    std::vector<std::unique_ptr<ConstrainedRCPrfElement<NBYTES>>>&
        constrained_elements) const
{
    if (min > max) {
        throw std::invalid_argument(
            "RCPrf::constrain: Invalid range: min is larger than max: max="
            + std::to_string(max) + ", min=" + std::to_string(min));
    }
    if (max >= RCPrfParams::leaf_count(this->tree_height())) {
        throw std::out_of_range(
            "RCPrf::constrain: range's maximum (=" + std::to_string(max)
            + ") is too big. It must be strictly smaller than 2^(height-1) "
              "(="
            + std::to_string(RCPrfParams::leaf_count(this->tree_height()))
            + ")");
    }

    if (max == RCPrfParams::leaf_count(this->tree_height()) - 1 && min == 0) {
        throw std::out_of_range(
            "RCPrf::constrain: the input range (" + std::to_string(min) + ", "
            + std::to_string(max)
            + ") is the complete range supported by the PRF.");
    }

    uint64_t max_range = RCPrfParams::leaf_count(this->tree_height()) - 1;
    RCPrfBase<NBYTES>::generate_constrained_subkeys_from_node(
        root_prg_,
        this->tree_height(),
        this->tree_height(),
        0,
        max_range,
        min,
        max,
        constrained_elements);
}

extern template class ConstrainedRCPrfLeafElement<16>;
extern template class ConstrainedRCPrfInnerElement<16>;
extern template class ConstrainedRCPrf<16>;
extern template class RCPrf<16>;

extern template class ConstrainedRCPrfLeafElement<32>;
extern template class ConstrainedRCPrfInnerElement<32>;
extern template class ConstrainedRCPrf<32>;
extern template class RCPrf<32>;

} // namespace crypto
} // namespace sse