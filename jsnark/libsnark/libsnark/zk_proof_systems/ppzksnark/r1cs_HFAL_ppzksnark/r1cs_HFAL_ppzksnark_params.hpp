#ifndef __HFAL_PARAMS_HPP__
#define __HFAL_PARAMS_HPP__

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>

namespace libsnark {

/**
 * Below are various template aliases (used for convenience).
 */

template<typename ppT>
using r1cs_gg_ppzksnark_constraint_system = r1cs_constraint_system<libff::Fr<ppT> >;

template<typename ppT>
using r1cs_gg_ppzksnark_primary_input = r1cs_primary_input<libff::Fr<ppT> >;

template<typename ppT>
using r1cs_gg_ppzksnark_auxiliary_input = r1cs_auxiliary_input<libff::Fr<ppT> >;

} // libsnark
#endif
