#ifndef HEADER_GUARD_70b3420b598719a4ebac1a15cf399474
#define HEADER_GUARD_70b3420b598719a4ebac1a15cf399474

/*
  Based on Boost Sandbox enable_if_macro.hpp
*/

/*==============================================================================
    Copyright (c) 2011, 2012 Matt Calabrese

    Use modification and distribution are subject to the Boost Software
    License, Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
    http://www.boost.org/LICENSE_1_0.txt).
==============================================================================*/

#include <boost/utility/enable_if.hpp>

namespace jbms { namespace enable_if_detail {

enum enabler_type { enabler_type_enabler };

template< class Dummy, bool C >
struct enable_if_c_impl {};

template< class Dummy >
struct enable_if_c_impl< Dummy, true > { typedef enabler_type type; };

template< class Dummy, bool C >
struct disable_if_c_impl {};

template< class Dummy >
struct disable_if_c_impl< Dummy, false > { typedef enabler_type type; };

template< class Dummy, class C >
struct enable_if_impl : enable_if_c_impl< Dummy, C::value > {};

template< class Dummy, class C >
struct disable_if_impl : disable_if_c_impl< Dummy, C::value > {};

template< class... T >
struct always_enabler_type { typedef enabler_type type; };

template< class... T > struct always_true { static bool const value = true; };

template< class... T > struct always_void { typedef void type; };

} }

#define JBMS_DECLARE_ENABLE_IF_PARAM_NO_DEFAULT() class

#define JBMS_DECLARE_ENABLE_IF_PARAM() class = void

#define JBMS_TYPE_ENABLE_IF( ... )                                            \
typename ::boost::enable_if_c< __VA_ARGS__::value >::type

#define JBMS_TYPE_ENABLE_IF_C( ... )                                          \
typename ::boost::enable_if_c< __VA_ARGS__ >::type

#define JBMS_TYPE_DISABLE_IF( ... )                                           \
typename ::boost::enable_if_c< !__VA_ARGS__::value >::type

#define JBMS_TYPE_DISABLE_IF_C( ... )                                         \
typename ::boost::enable_if_c< !__VA_ARGS__ >::type

#define JBMS_ENABLE_IF_C( ... )                                               \
JBMS_ENABLE_IF_DEFINITION_C( __VA_ARGS__ )                                    \
= ::jbms::enable_if_detail::enabler_type_enabler

#define JBMS_ENABLE_IF_DEFINITION_C( ... )                                    \
class BoostDetailEnableIfDependentType = void,                                 \
typename ::jbms::enable_if_detail::enable_if_c_impl                           \
< BoostDetailEnableIfDependentType                                             \
, ( __VA_ARGS__ )                                                              \
>::type

#define JBMS_DISABLE_IF_C( ... )                                              \
JBMS_DISABLE_IF_DEFINITION_C( __VA_ARGS__ )                                   \
= ::jbms::enable_if_detail::enabler_type_enabler

#define JBMS_DISABLE_IF_DEFINITION_C( ... )                                   \
class BoostDetailDisableIfDependentType = void,                                \
typename ::jbms::enable_if_detail::disable_if_c_impl                          \
< BoostDetailDisableIfDependentType                                            \
, ( __VA_ARGS__ )                                                              \
>::type

#define JBMS_ENABLE_IF( ... )                                                 \
class BoostDetailEnableIfDependentType = void,                                 \
typename ::jbms::enable_if_detail::enable_if_impl                             \
< BoostDetailEnableIfDependentType                                             \
, __VA_ARGS__                                                                  \
>::type = ::jbms::enable_if_detail::enabler_type_enabler

#define JBMS_DISABLE_IF( ... )                                                \
class BoostDetailDisableIfDependentType = void,                                \
typename ::jbms::enable_if_detail::disable_if_impl                            \
< BoostDetailDisableIfDependentType                                            \
, __VA_ARGS__                                                                  \
>::type = ::jbms::enable_if_detail::enabler_type_enabler

#define JBMS_DISABLE() JBMS_DISABLE_IF_C( true )

#define JBMS_DISABLED_FUNCTION( name ) template< JBMS_DISABLE() >            \
void name( ... );

#define JBMS_ENABLE_IF_VALID_TYPE( ... )                                      \
typename ::jbms::enable_if_detail::always_enabler_type< __VA_ARGS__ >::type   \
= ::jbms::enable_if_detail::enabler_type_enabler

#define JBMS_ENABLE_IF_EXPR( ... )                              \
typename ::jbms::enable_if_detail::always_enabler_type                        \
< decltype( __VA_ARGS__ ) >::type                                              \
= ::jbms::enable_if_detail::enabler_type_enabler

#define JBMS_TYPE_ENABLE_IF_VALID_TYPE( ... )                                 \
typename ::jbms::enable_if_detail::always_void< __VA_ARGS__ >::type

#define JBMS_TYPE_ENABLE_IF_EXPR( ... )                         \
typename ::jbms::enable_if_detail::always_void< decltype( __VA_ARGS__ ) >::type

#endif /* HEADER GUARD */
