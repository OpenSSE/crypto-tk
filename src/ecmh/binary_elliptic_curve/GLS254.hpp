#ifndef HEADER_GUARD_4B34A7DDCF2B5EB0F2741F22604469BC
#define HEADER_GUARD_4B34A7DDCF2B5EB0F2741F22604469BC
#include "ecmh/binary_field/GF2_254.hpp"
namespace jbms {
namespace binary_elliptic_curve {
class GLS254 {
public:
  using Field = jbms::binary_field::GF2_254;
  constexpr static Field field() { return {}; }
  constexpr static size_t num_compressed_bytes() {
    return field().num_bytes();
  }
public:
  constexpr static jbms::binary_field::QuadraticU<jbms::binary_field::One> const a() { return {}; }
private:
  static const GLS254::Field::BaseField::Element b_;
public:
  constexpr static GLS254::Field::BaseField::Element const &b() { return b_; }
private:
  static const GLS254::Field::BaseField::Element sqrt_b_;
public:
  constexpr static GLS254::Field::BaseField::Element const &sqrt_b() { return sqrt_b_; }
};
} // namespace jbms::binary_elliptic_curve
} // namespace jbms
#endif // HEADER GUARD
