#ifndef HEADER_GUARD_95ae887627257fc4acf80142985c9726
#define HEADER_GUARD_95ae887627257fc4acf80142985c9726

#include "./Point.hpp"

namespace jbms {
namespace binary_elliptic_curve {

// Sets result := P + P
// result may alias P
template <class Curve, class Point, JBMS_ENABLE_IF(is_lambda_point<Curve,Point>)>
void double_point(Curve const &curve,
                  LambdaProjectivePoint<Curve> &result,
                  Point const &P) {

  auto &&F = curve.field();

  if (is_zero(F, P.x())) {
    // If P.x == 0, then either P = infinity, or P = (0,sqrt(b))
    // Either way, the result is infinity.
    set_infinity(curve, result);
  } else {

    // affine: no-op
    // full: 1 multiply
    auto PmPz = multiply(F, P.m(), P.z()); // P.m() * P.z()

    // affine: no-op
    // full: 1 square
    auto Pz2 = square(F, P.z()); // P.z()^2

    // affine: 2 add + 1 square
    // full: 2 add + 1 square + 1 multiply
    auto T = add(F, add(F, square(F, P.m()), PmPz), multiply(F, curve.a(), Pz2)); // P.m()^2 + PmPz + Pz^2 + curve.a()
    if (is_zero(F, T)) {
      // T == 0 iff result.x == 0
      // Therefore, we know that we ended up at the (x = 0, curve.sqrt_b()) point
      set_non_lambda_point(curve, result);
    }
    else {
      auto PxPz = multiply(F, P.x(), P.z());

      // regular or affine: 1 square
      square(F, result.x(), T); // result.x() = T^2

      // affine: no-op
      // full: 1 multiply
      multiply(F, result.z(), T, Pz2); // result.z() = T * Pz^2

      // result.m() = (P.x() * P.z())^2 + result.x() + T * PmPz + result.z()
      // full: 3 add + 1 square + 2 multiply
      // affine: 3 add + 1 square + 1 multiply
      add(F, result.m(), add(F, add(F, square(F, PxPz), result.x()), multiply(F, T, PmPz)), result.z());
    }

    // affine total: 5 add + 3 square + 1 multiply
    // regular total: 5 multiply + 4 square + 5 add
  }
}

/**
 * Sets result := Q + (x=0,y=curve.sqrt_b())
 *
 * result may alias Q
 *
 * (x=0,y=curve.sqrt_b()) is the single valid point with x = 0, and is the only valid point that cannot be represented using lambda coordinates.
 **/
template <class Curve, class Point, JBMS_ENABLE_IF(is_lambda_point<Curve,Point>)>
void add_non_lambda_point(Curve const &curve, LambdaProjectivePoint<Curve> &result, Point const &Q) {
  auto &&F = curve.field();
  auto Qz = Q.z(); // make copy in case &result == &Q
  multiply(F, result.z(), Q.x(), Qz);
  multiply(F, result.m(), Q.x(), add(F, Q.m(), Qz));
  multiply(F, result.x(), curve.sqrt_b(), square(F, Qz)); // sqrt(b) * Q.z()^2
}

/**
 * Sets result := P + Q
 *
 * result may alias P and/or Q
 * P may alias Q
 **/
template <class Curve, class Point1, class Point2,
          JBMS_ENABLE_IF_C(is_lambda_point<Curve,Point1>::value &&
                           is_lambda_point<Curve,Point2>::value)>
void add(Curve const &curve,
         LambdaProjectivePoint<Curve> &result,
         Point1 const &P,
         Point2 const &Q) {

  auto &&F = curve.field();

  if (is_infinity(curve, Q)) {
    assign(curve, result, P);
  } else if (is_infinity(curve, P)) {
    assign(curve, result, Q);
  } else if (is_zero(F, P.x())) {
    if (is_zero(F, Q.x()))
      set_infinity(curve, result);
    else
      add_non_lambda_point(curve, result, Q);
  } else if (is_zero(F, Q.x())) {
    add_non_lambda_point(curve, result, P);
  } else {
    // full: 2 multiply
    // affine: no-op
    // mixed: 1 multiply
    auto QxPz = multiply(F, Q.x(), P.z());
    auto PxQz = multiply(F, P.x(), Q.z());

    // full: 1 add + 2 multiply
    // affine: 1 add
    // mixed: 1 add + 1 multiply
    auto A = add(F, multiply(F, P.m(), Q.z()), multiply(F, Q.m(), P.z())); // P.m() * Q.z() + Q.m() * P.z()
    // A == 0 iff m_P = m_Q

    // any: 1 add
    auto B_sqrt = add(F, QxPz, PxQz); // PxQz + QxPz

    if (is_zero(F, A)) {
      // B_sqrt == 0 iff x_P = x_Q
      if (is_zero(F, B_sqrt)) {
        double_point(curve, result, P);
      } else {
        set_non_lambda_point(curve, result);
        // P + Q =  (0, sqrt(curve.b()))
      }
    } else {
      if (is_zero(F, B_sqrt)) {
        // B_sqrt == 0 iff x_P = x_Q
        // since we know A != 0, we know that P != Q
        // The only other option is that P = -Q

        set_infinity(curve, result);
      } else {

        // any: 1 square
        auto B = square(F, B_sqrt); // (PxQz + QxPz)^2

        // full: 3 multiply
        // affine: 1 multiply
        // mixed: 2 multiply
        auto ABPz = multiply(F, multiply(F, A, B), P.z()); // A * B * P.z()

        // any: 3 multiply
        auto AQxPz = multiply(F, A, QxPz); // A * Q.x() * P.z()
        auto APxQz = multiply(F, A, PxQz); // A * P.x() * Q.z()
        multiply(F, result.x(), APxQz, AQxPz); // APxQz * AQxPz

        // full: 3 add + 1 square + 1 multiply
        // affine: 2 add + 1 square + 1 multiply
        // mixed: 2/3 add + 1 square + 1 multiply
        add(F, result.m(), square(F, add(F, APxQz, B)), multiply(F, ABPz, add(F, Q.m(), Q.z())));
        // result.m() = (APxQz + B)^2 + ABPz * (Q.m() + Q.z())

        multiply(F, result.z(), ABPz, Q.z()); // ABPz * Q.z() = A * B * P.z() * Q.z()
      }
    }
  }

  // full total: 5 add + 11 multiply + 2 square
  // affine total: 4 add + 5 multiply + 2 square
  // mixed total: 5 add + 8 multiply + 2 square
}

template <class Curve,
          class Point1,
          class Point2,
          JBMS_ENABLE_IF_C(is_lambda_point<Curve, Point1>::value &&is_lambda_point<Curve, Point2>::value)>
LambdaProjectivePoint<Curve> add(Curve const &curve, Point1 const &P, Point2 const &Q) {
  LambdaProjectivePoint<Curve> result;
  add(curve, result, P, Q);
  return result;
}

template <class Curve, class Point1,
          JBMS_ENABLE_IF_C(is_lambda_point<Curve,Point1>::value)>
LambdaProjectivePoint<Curve> double_point(Curve const &curve,
                                          Point1 const &P) {
  LambdaProjectivePoint<Curve> result;
  double_point(curve, result, P);
  return result;
}


}
}

#endif /* HEADER GUARD */
