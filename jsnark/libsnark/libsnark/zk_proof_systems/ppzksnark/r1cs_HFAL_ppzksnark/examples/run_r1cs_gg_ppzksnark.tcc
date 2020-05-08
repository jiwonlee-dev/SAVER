/** @file
 *****************************************************************************

 Implementation of functionality that runs the R1CS GG-ppzkSNARK for
 a given R1CS example.

 See run_r1cs_gg_ppzksnark.hpp .

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef RUN_R1CS_GG_PPZKSNARK_TCC_
#define RUN_R1CS_GG_PPZKSNARK_TCC_

#include <sstream>
#include <type_traits>

#include <libff/common/profiling.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_HFAL_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_HFAL_ppzksnark/r1cs_HFAL_XP1_ppzksnark.hpp>

namespace libsnark {

template<typename ppT>
typename std::enable_if<ppT::has_affine_pairing, void>::type
test_affine_verifier(const r1cs_gg_ppzksnark_verification_key<ppT> &vk,
                     const accumulation_vector<libff::G1<ppT> > &cx ,
                     const r1cs_gg_ppzksnark_proof<ppT> &proof,
                     const bool expected_answer)
{
    libff::print_header("R1CS GG-ppzkSNARK Affine Verifier");
    const bool answer = r1cs_gg_ppzksnark_affine_verifier_weak_IC<ppT>(vk, cx, proof);
    assert(answer == expected_answer);
}

template<typename ppT>
typename std::enable_if<!ppT::has_affine_pairing, void>::type
test_affine_verifier(const r1cs_gg_ppzksnark_verification_key<ppT> &vk,
                     const accumulation_vector<libff::G1<ppT> > &cx ,
                     const r1cs_gg_ppzksnark_proof<ppT> &proof,
                     const bool expected_answer)
{
    libff::print_header("R1CS GG-ppzkSNARK Affine Verifier");
    libff::UNUSED(vk, cx, proof, expected_answer);
    printf("Affine verifier is not supported; not testing anything.\n");
}

/**
 * The code below provides an example of all stages of running a R1CS GG-ppzkSNARK.
 *
 * Of course, in a real-life scenario, we would have three distinct entities,
 * mangled into one in the demonstration below. The three entities are as follows.
 * (1) The "generator", which runs the ppzkSNARK generator on input a given
 *     constraint system CS to create a proving and a verification key for CS.
 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
 *     a primary input for CS, and an auxiliary input for CS.
 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
 *     a primary input for CS, and a proof.
 */
template<typename ppT>
bool run_r1cs_gg_ppzksnark(const r1cs_example<libff::Fr<ppT> > &example,
                        const bool test_serialization)
{
    libff::Fr<ppT> a("hello");
    a.print();
	libff::print_header("HFAL XP1 SETUP");
    libff::enter_block("Call to HFAL_xp1_setup");
    r1cs_HFAL_XP1_ppzksnark_pp<ppT> xp1_pp_g1 = r1cs_HFAL_XP1_ppzksnark_setup<ppT>(example.primary_input);
    libff::leave_block("Call to HFAL_xp1_setup");

	libff::print_header("HFAL XP1 HASHING");
    libff::enter_block("Call to HFAL_xp1_hash");
    r1cs_HFAL_XP1_ppzksnark_hash<ppT> xp1_hash = r1cs_HFAL_XP1_ppzksnark_hashing<ppT>(xp1_pp_g1,example.primary_input);
    libff::leave_block("Call to HFAL_xp1_hash");

	printf("\n");
    libff::enter_block("Call to run_r1cs_gg_ppzksnark");

    libff::print_header("R1CS GG-ppzkSNARK Generator");
    r1cs_gg_ppzksnark_keypair<ppT> keypair = r1cs_gg_ppzksnark_generator<ppT>(example.constraint_system);
    printf("\n"); libff::print_indent(); libff::print_mem("after generator");

    libff::print_header("Preprocess verification key");
    r1cs_gg_ppzksnark_processed_verification_key<ppT> pvk = r1cs_gg_ppzksnark_verifier_process_vk<ppT>(keypair.vk);

    if (test_serialization)
    {
        libff::enter_block("Test serialization of keys");
        keypair.pk = libff::reserialize<r1cs_gg_ppzksnark_proving_key<ppT> >(keypair.pk);
        keypair.vk = libff::reserialize<r1cs_gg_ppzksnark_verification_key<ppT> >(keypair.vk);
        pvk = libff::reserialize<r1cs_gg_ppzksnark_processed_verification_key<ppT> >(pvk);
        libff::leave_block("Test serialization of keys");
    }

    const accumulation_vector<libff::G1<ppT> > cx = pvk.gamma_ABC_g1.template accumulate_chunk<libff::Fr<ppT> >(example.primary_input.begin(), example.primary_input.end(), 0);

	libff::print_header("HFAL XP1 KEY Generation");
    libff::enter_block("Call to HFAL_xp1_Generator");
    r1cs_HFAL_XP1_ppzksnark_keypair<ppT> xp1_keypair(r1cs_HFAL_XP1_ppzksnark_generator<ppT>(xp1_pp_g1, pvk.gamma_ABC_g1));
    libff::leave_block("Call to HFAL_xp1_Generator");

	libff::print_header("HFAL XP1 KEY Prover");
    libff::enter_block("Call to HFAL_xp1_prover");
    r1cs_HFAL_XP1_ppzksnark_proof<ppT> xp1_proof = r1cs_HFAL_XP1_ppzksnark_prover<ppT>(xp1_keypair.pk, example.primary_input, cx);
    libff::leave_block("Call to HFAL_xp1_prover");

	libff::print_header("HFAL XP1 KEY Verifier");
    libff::enter_block("Call to HFAL_xp1_verifier");
    const bool xp1_ans = r1cs_HFAL_XP1_ppzksnark_verifier<ppT>(xp1_keypair.vk, xp1_hash, cx,xp1_proof);
    libff::leave_block("Call to HFAL_xp1_verifier");

    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The XP1 verification result is: %s\n", (xp1_ans ? "PASS" : "FAIL"));

	printf("\n");
    libff::print_header("R1CS GG-ppzkSNARK Prover");
    r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(keypair.pk, example.primary_input, example.auxiliary_input);
    printf("\n"); libff::print_indent(); libff::print_mem("after prover");

    if (test_serialization)
    {
        libff::enter_block("Test serialization of proof");
        proof = libff::reserialize<r1cs_gg_ppzksnark_proof<ppT> >(proof);
        libff::leave_block("Test serialization of proof");
    }

    libff::print_header("R1CS GG-ppzkSNARK Verifier");
    const bool ans = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, cx, proof);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

    libff::print_header("R1CS GG-ppzkSNARK Online Verifier");
    const bool ans2 = r1cs_gg_ppzksnark_online_verifier_strong_IC<ppT>(pvk, cx, proof);
    assert(ans == ans2);
	
    test_affine_verifier<ppT>(keypair.vk, cx, proof, ans);

    libff::leave_block("Call to run_r1cs_gg_ppzksnark");

    return ans==ans2;
}

} // libsnark

#endif // RUN_R1CS_GG_PPZKSNARK_TCC_
