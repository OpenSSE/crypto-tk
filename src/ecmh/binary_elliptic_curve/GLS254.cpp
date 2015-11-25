#include "./GLS254.hpp"
namespace jbms {
namespace binary_elliptic_curve {
GLS254::Field::BaseField::Element const GLS254::b_ {jbms::binary_field::BinaryPolynomial<127>{(uint64_t)0x2e6d944fa54de7e5ul, (uint64_t)0x59c8202cb9e6e0aeul}};
GLS254::Field::BaseField::Element const GLS254::sqrt_b_ {jbms::binary_field::BinaryPolynomial<127>{(uint64_t)0xae81985e2b6b3bbbul, (uint64_t)0x2a46edcf5cc52f13ul}};
} // namespace jbms::binary_elliptic_curve
} // namespace jbms
