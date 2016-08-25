#ifndef HEADER_GUARD_7340e909066222836455db26f874c59d
#define HEADER_GUARD_7340e909066222836455db26f874c59d

#include "ecmh/utility/enable_if.hpp"
#include <boost/range/iterator_range.hpp>
#include <boost/range/value_type.hpp>
#include "ecmh/binary_field/detail/field_operation_helpers.hpp"
#include <type_traits>
#include <algorithm>
#include <string>

namespace jbms {
namespace binary_elliptic_curve {

template <class Curve>
struct AffinePoint;

template <class Curve>
struct LambdaAffinePoint;

template <class Curve>
struct LambdaProjectivePoint;


template <class Curve, class Point>
struct is_lambda_point : std::false_type{};

template <class Curve>
struct is_lambda_point<Curve,LambdaAffinePoint<Curve>> : std::true_type{};

template <class Curve>
struct is_lambda_point<Curve,LambdaProjectivePoint<Curve>> : std::true_type{};

template <class Curve>
void assign(Curve const &curve, AffinePoint<Curve> &result, AffinePoint<Curve> const &P) {
  result = P;
}

template <class Curve>
void assign(Curve const &curve, LambdaAffinePoint<Curve> &result, LambdaAffinePoint<Curve> const &P) {
  result = P;
}

template <class Curve>
void assign(Curve const &curve, LambdaProjectivePoint<Curve> &result, LambdaProjectivePoint<Curve> const &P) {
  result = P;
}

template <class Curve>
void assign(Curve const &curve, AffinePoint<Curve> &result, LambdaAffinePoint<Curve> const &P) {
  auto &&F = curve.field();
  result.x() = P.x();
  if (is_zero(F, result.x())) {
    // special case: x = 0 point
    assign(F, result.y(), curve.sqrt_b());
  } else {
    multiply(F, result.y(), result.x(), add(F, P.m(), result.x()));
  }
}

template <class Curve>
void assign(Curve const &curve, LambdaAffinePoint<Curve> &result, AffinePoint<Curve> const &P) {
  auto &&F = curve.field();

  result.x() = P.x();
  if (is_zero(F, result.x())) {
    // special case: x = 0  (y = sqrt(b))
    set_zero(F, result.m());
  } else {
    add(F, result.m(), result.x(), multiply(F, P.y(), invert(F, result.x())));
  }
}

template <class Curve>
void assign(Curve const &curve, LambdaProjectivePoint<Curve> &result, AffinePoint<Curve> const &P) {
  auto &&F = curve.field();
  square(F, result.x(), P.x());

  if (is_zero(F, P.x())) {
    // P = (x=0,y=sqrt(b))
    // we represent this point specially
    set_zero(F, result.m());
  }
  else {
    add(F, result.m(), result.x(), P.y());
  }

  result.z() = P.x();
}

template <class Curve>
void assign(Curve const &curve, LambdaProjectivePoint<Curve> &result, LambdaAffinePoint<Curve> const &P) {
  auto &&F = curve.field();
  result.x() = P.x();
  result.m() = P.m();
  set_one(F, result.z());
}

// Precondition: P != infinity
template <class Curve>
void assign(Curve const &curve, LambdaAffinePoint<Curve> &result, LambdaProjectivePoint<Curve> const &P) {
  auto z_inv = invert(curve.field(), P.z());
  multiply(curve.field(), result.x(), P.x(), z_inv);
  multiply(curve.field(), result.m(), P.m(), z_inv);
}

// Precondition: P != infinity
template <class Curve>
void assign(Curve const &curve, AffinePoint<Curve> &result, LambdaProjectivePoint<Curve> const &P) {
  LambdaAffinePoint<Curve> P1;
  assign(curve, P1, P);
  assign(curve, result, P1);
}


template <class Curve>
struct AffinePoint {
  using Field = typename Curve::Field;
  using FE = typename Field::Element;

  FE x_, y_;

  FE &x() { return x_; }
  FE const &x() const { return x_; }

  FE &y() { return y_; }
  FE const &y() const { return y_; }

  AffinePoint() = default;
  AffinePoint(FE const &x_in, FE const &y_in)
    : x_(x_in), y_(y_in)
  {}

  explicit AffinePoint(Curve const &curve, LambdaAffinePoint<Curve> const &P) {
    assign(curve, *this, P);
  }
};

template <class Curve>
inline void negate(Curve const &curve, AffinePoint<Curve> &result, AffinePoint<Curve> const &P) {
  result.x() = P.x();
  result.y() = add(curve.field(), P.x(), P.y());
}

template <class Curve>
inline AffinePoint<Curve> negate(Curve const &curve, AffinePoint<Curve> const &P) {
  AffinePoint<Curve> result;
  negate(curve, result, P);
  return result;
}

/**
 * Checks if P satisfies the curve equation:
 * y^2 + x * y = x^3 + a * x^2 + b
 **/
template <class Curve>
bool is_rational(Curve const &curve, AffinePoint<Curve> const &P) {
  auto &&F =  curve.field();

  auto y2 = square(F, P.y());
  auto x2 = square(F, P.x());
  auto x3 = multiply(F, x2, P.x());
  auto xy = multiply(F, P.x(), P.y());

  auto lhs = add(F, y2, xy);
  auto rhs = add(F, add(F, x3, multiply(F, curve.a(), x2)), curve.b());

  return equal(F, lhs, rhs);
}

template <class Curve>
struct LambdaAffinePoint {
  using Field = typename Curve::Field;
  using FE = typename Field::Element;

private:
  FE x_, m_;
public:
  // m = x + y/x = (x^2 + y) / x

  static constexpr jbms::binary_field::One z() { return {}; }

  LambdaAffinePoint() = default;
  LambdaAffinePoint(FE const &x_in, FE const &m_in)
    : x_(x_in), m_(m_in)
  {}

  FE &x() { return x_; }
  FE const &x() const { return x_; }

  FE &m() { return m_; }
  FE const &m() const { return m_; }

  explicit LambdaAffinePoint(Curve const &curve, AffinePoint<Curve> const &P) {
    assign(curve, *this, P);
  }


  // no preconditions
  friend LambdaAffinePoint<Curve> const &assume_affine(LambdaAffinePoint<Curve> const &P) {
    return P;
  }

  friend LambdaAffinePoint<Curve> &assume_affine(LambdaAffinePoint<Curve> &P) {
    return P;
  }
};

template <class Curve>
inline void negate(Curve const &curve, LambdaAffinePoint<Curve> &result, LambdaAffinePoint<Curve> const &P) {
  result.x() = P.x();
  // result.x = P.x
  // result.m = P.x + (P.y + P.x)/P.x =  P.x + P.y/P.x + P.x/P.x = P.m + 1
  if (is_zero(curve.field(), result.x())) {
    // special x=0 point
    set_zero(curve.field(), result.m());
  } else {
    add(curve.field(), result.m(), P.m(), one_expr(curve.field()));
  }
}

template <class Curve>
inline LambdaAffinePoint<Curve> negate(Curve const &curve, LambdaAffinePoint<Curve> const &P) {
  LambdaAffinePoint<Curve> result;
  negate(curve, result, P);
  return result;
}


/**
 * Checks if P satisfies the curve equation:
 * (m^2 + m + a) * x^2 = x^4 + b
 **/
template <class Curve>
bool is_rational(Curve const &curve, LambdaAffinePoint<Curve> const &P) {
  auto &&F =  curve.field();

  if (is_zero(F, P.x())) {
    if (is_zero(F, P.m())) {
      // special non-lambda point
      return true;
    }
    return false;
  }

  auto m2 = square(F, P.m());
  auto x2 = square(F, P.x());
  auto x4 = square(F, x2);

  auto lhs = multiply(F, add(F, add(F, m2, P.m()), curve.a()), x2);
  auto rhs = add(F, x4, curve.b());

  return equal(F, lhs, rhs);
}

/**
 * Checks if P is infinity or satisfies the curve equation:
 *   (m^2/z^2 + m/z + a) * x^2/z^2 = x^4/z^4 + b
 *
 *       multiply both sides by z^4:
 *
 *    (m^2 + m z + a z^2) * x^2 = x^4 + b z^4
 *
 **/
template <class Curve>
bool is_rational(Curve const &curve, LambdaProjectivePoint<Curve> const &P) {
  auto &&F =  curve.field();

  if (is_infinity(curve, P)) return true;
  if (is_zero(F, P.x())) {
    if (is_zero(F, P.m())) {
      // special non-lambda point
      return true;
    }
    return false;
  }

  auto m2 = square(F, P.m());
  auto x2 = square(F, P.x());
  auto x4 = square(F, x2);
  auto z2 = square(F, P.z());
  auto z4 = square(F, z2);

  auto lhs = multiply(F, add(F, add(F, m2, multiply(F, P.m(), P.z())), multiply(F, curve.a(), z2)), x2);
  auto rhs = add(F, x4, multiply(F, curve.b(), z4));

  return equal(F, lhs, rhs);
}

template <class Curve>
struct LambdaProjectivePoint : private LambdaAffinePoint<Curve> {
  using Field = typename Curve::Field;
  using FE = typename Field::Element;

  using LambdaAffinePoint<Curve>::x;
  using LambdaAffinePoint<Curve>::m;

private:
  FE z_;
public:

  FE &z() { return z_; }
  FE const &z() const { return z_; }

  LambdaProjectivePoint() = default;
  LambdaProjectivePoint(FE const &x_in, FE const &m_in, FE const &z_in)
    : LambdaAffinePoint<Curve>(x_in,m_in), z_(z_in)
  {}

  explicit LambdaProjectivePoint(Curve const &curve, AffinePoint<Curve> const &P) {
    assign(curve, *this, P);
  }
  explicit LambdaProjectivePoint(Curve const &curve, LambdaAffinePoint<Curve> const &P) {
    assign(curve, *this, P);
  }

  /**
   * Precondition: z == 1
   **/
  friend LambdaAffinePoint<Curve> const &assume_affine(LambdaProjectivePoint<Curve> const &P) {
    return P;
  }

  friend LambdaAffinePoint<Curve> &assume_affine(LambdaProjectivePoint<Curve> &P) {
    return P;
  }
};

template <class Curve>
constexpr bool is_affine(Curve const &curve, LambdaAffinePoint<Curve> const &P) { return true; }

template <class Curve>
bool is_affine(Curve const &curve, LambdaProjectivePoint<Curve> const &P) {
  auto &&F = curve.field();
  return is_one(F, P.z());
}

template <class Curve>
void set_infinity(Curve const &curve, LambdaProjectivePoint<Curve> &P) {
  auto &&F = curve.field();
  set_zero(F, P.x());
  set_one(F, P.m());
  set_zero(F, P.z());
}

template <class Curve>
inline bool is_infinity(Curve const &curve, LambdaProjectivePoint<Curve> const &P) {
  auto &&F = curve.field();
  return is_zero(F, P.z());
}

template <class Curve>
constexpr bool is_infinity(Curve const &curve, LambdaAffinePoint<Curve> const &P) { return false; }

template <class Curve>
constexpr bool is_infinity(Curve const &curve, AffinePoint<Curve> const &P) { return false; }

template <class Curve>
void set_non_lambda_point(Curve const &curve, AffinePoint<Curve> &P) {
  set_zero(curve.field(), P.x());
  P.m() = curve.sqrt_b();
}

template <class Curve>
void set_non_lambda_point(Curve const &curve, LambdaAffinePoint<Curve> &P) {
  set_zero(curve.field(), P.x());
  set_zero(curve.field(), P.m());
}

template <class Curve>
void set_non_lambda_point(Curve const &curve, LambdaProjectivePoint<Curve> &P) {
  set_zero(curve.field(), P.x());
  set_zero(curve.field(), P.m());
  set_one(curve.field(), P.z());
}



// Sets result := -P
// result may alias P
template <class Curve>
inline void negate(Curve const &curve, LambdaProjectivePoint<Curve> &result, LambdaProjectivePoint<Curve> const &P) {
  // result.x = P.x / P.z
  // result.m = P.m / P.z + 1 = (P.m + P.z) / P.z

  // Note: this formula works for infinity (P.z == 0) as well, so we don't need to special case
  result.x() = P.x();
  if (is_zero(curve.field(), result.x())) {
    // special x=0 point
    set_zero(curve.field(), result.m());
  } else {
    add(curve.field(), result.m(), P.m(), P.z());
  }
  result.z() = P.z();
}

template <class Curve>
inline LambdaProjectivePoint<Curve> negate(Curve const &curve, LambdaProjectivePoint<Curve> const &P) {
  LambdaProjectivePoint<Curve> result;
  negate(curve, result, P);
  return result;
}

template <class Curve, class Point1, class Point2, JBMS_ENABLE_IF_C(is_lambda_point<Curve,Point1>::value &&
                                                                    is_lambda_point<Curve,Point2>::value)>
bool equal(Curve const &curve, Point1 const &P, Point2 const &Q) {
  auto &&F = curve.field();
  bool inf_P = is_infinity(curve, P), inf_Q = is_infinity(curve, Q);
  return inf_P ? inf_Q :
    !inf_Q && (equal(F, multiply(F, P.x(), Q.z()), multiply(F, Q.x(), P.z())) &&
               equal(F, multiply(F, P.m(), Q.z()), multiply(F, Q.m(), P.z())));
}

template <class Curve>
bool equal(Curve const &curve, AffinePoint<Curve> const &P, AffinePoint<Curve> const &Q) {
  auto &&F = curve.field();
  return equal(F, P.x(), Q.x()) && equal(F, P.y(), Q.y());
}

template <class Curve>
std::string to_affine_hex(Curve const &curve, AffinePoint<Curve> const &point) {
  return to_hex(curve.field(), point.x()) + " " + to_hex(curve.field(), point.y());
}

template <class Curve, class Point, JBMS_ENABLE_IF(is_lambda_point<Curve,Point>)>
std::string to_affine_hex(Curve const &curve, Point const &point) {
  if (is_infinity(curve, point))
    return "inf";
  AffinePoint<Curve> P;
  assign(curve, P, point);
  return to_affine_hex(curve, P);
}



template <class Curve>
void assign_from_affine_hex(Curve const &curve, LambdaProjectivePoint<Curve> &P, std::string const &s) {
  if (s == "inf")
    set_infinity(curve, P);
  else {
    auto sep_it = std::find(s.begin(), s.end(), ' ');
    if (sep_it == s.end())
      throw std::invalid_argument("Curve affine hex representation must contain a space");

    AffinePoint<Curve> Pa;
    assign_from_hex(curve.field(), Pa.x(), boost::make_iterator_range(s.begin(), sep_it));
    ++sep_it;
    assign_from_hex(curve.field(), Pa.y(), boost::make_iterator_range(sep_it, s.end()));
    assign(curve, P, Pa);
  }
}


// Precondition: x != 0
// Postcondition: m^2 + m = x^2 + x^{-2} b + a   if Tr(x^2 + x^{-2} b + a) == 0
// m + 1 is also a valid solution
template <class Curve>
void
valid_lambda_from_non_zero_x(Curve const &curve, typename Curve::Field::Element &m, typename Curve::Field::Element const &x) {

  // y^2 + xy = x^3 + ax^2 + b.

  // m = x + y/x

  // m^2 + m =  x^2 + y^2/x^2 + x + y/x

  // x^2 ( m^2 + m ) =  x^4 + y^2 + x^3 + yx

  // other side must have x^4  ax^2  b

  // x^2 + ax + b
  // (\lambda^2 + \lambda + a) x^2 = x^4 + b

  // we need  \lambda^2 + \lambda =  x^{-2} * (x^4 + b)  + a
  // i.e.    \lambda^2 + \lambda = x^2 + x^{-2} b + a
  // two solutions

  auto x2 = square(curve.field(), x);
  auto x2_inv = invert(curve.field(), x2);
  auto sum = add(curve.field(), curve.a(), add(curve.field(), x2, multiply(curve.field(), x2_inv, curve.b())));
  solve_quadratic(curve.field(), m, sum);
}



}
}

#endif /* HEADER GUARD */
