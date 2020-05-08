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
#include <fstream>
#include <iostream>

#include <libff/common/profiling.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/SAVER/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/SAVER/SNARK_friendly.hpp>

#define File
namespace libsnark
{

template <typename ppT>
typename std::enable_if<ppT::has_affine_pairing, void>::type
test_affine_verifier(const r1cs_gg_ppzksnark_verification_key<ppT> &vk,
                     const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input,
                     const r1cs_gg_ppzksnark_proof<ppT> &proof,
                     const bool expected_answer)
{
    libff::print_header("R1CS GG-ppzkSNARK Affine Verifier");
    const bool answer = r1cs_gg_ppzksnark_affine_verifier_weak_IC<ppT>(vk, primary_input, proof);
    assert(answer == expected_answer);
}

template <typename ppT>
typename std::enable_if<!ppT::has_affine_pairing, void>::type
test_affine_verifier(const r1cs_gg_ppzksnark_verification_key<ppT> &vk,
                     const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input,
                     const r1cs_gg_ppzksnark_proof<ppT> &proof,
                     const bool expected_answer)
{
    libff::print_header("R1CS GG-ppzkSNARK Affine Verifier");
    libff::UNUSED(vk, primary_input, proof, expected_answer);
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
template <typename ppT>
bool run_r1cs_gg_ppzksnark(const r1cs_example<libff::Fr<ppT>> &example,
                           const bool test_serialization, int msg, int MSG_BLOCK)
{

    libff::enter_block("Call to run_r1cs_gg_ppzksnark");

    r1cs_gg_ppzksnark_keypair<ppT> keypair;
    r1cs_gg_ppzksnark_processed_verification_key<ppT> pvk;
    SF_keypair<ppT> SF_key;
    vector<SF_cypher_text<ppT>> SF_ct_array;
    SF_plain_text<ppT> SF_pt;
    bool ans = false;
    bool ans_enc = false;

    printf("SIZE:::%d\n", example.auxiliary_input.size());
    libff::print_header("R1CS GG-ppzkSNARK Generator");

    libff::enter_block("R1CS GG-ppzkSNARK Generator");
    keypair = r1cs_gg_ppzksnark_generator<ppT>(example.constraint_system);
    libff::leave_block("R1CS GG-ppzkSNARK Generator");

    libff::print_header("SNARK Friendly Enc/Dec Key Generator");

    libff::enter_block("SF_key Generation");
    SF_key = SF_key_generator(keypair, MSG_BLOCK);
    libff::leave_block("SF_key Generation");

    libff::print_header("SNARK Friendly Encryption 1");

    std::string m = "";
    if(msg < 0)
    {
        m += "0000000F";
        for (int i = 1; i < MSG_BLOCK; i++)
            m += "0000000F";
    }
    else
    {
        for (int i = 0; i < msg - 1; i++)
            m += "00000000";
        m += "00000001";
        for (int i = msg; i < MSG_BLOCK; i++)
            m += "00000000";
    }

    libff::enter_block("SF Encrypt");
    SF_cypher_text<ppT> SF_ct1 = SF_encrypt(keypair,
                                            SF_key.pk,
                                            m, MSG_BLOCK,
                                            example.primary_input,
                                            example.auxiliary_input); // Create Enc Proof
    libff::leave_block("SF Encrypt");

    libff::enter_block("SF Rerandomize");
    SF_cypher_text<ppT> SF_ct2 = SF_rerandomize(keypair, SF_key.pk, SF_ct1);
    libff::leave_block("SF Rerandomize");

    ans_enc = SF_enc_verifier(keypair, SF_key.pk, SF_ct1); //Encryption Proof
    printf("* The verification :result is: %s\n", (ans_enc ? "PASS" : "FAIL"));

    libff::enter_block("SF Enc Verifier");
    ans_enc = SF_enc_verifier(keypair, SF_key.pk, SF_ct2); //Encryption Proof
    printf("* The verification :result is: %s\n", (ans_enc ? "PASS" : "FAIL"));
    libff::leave_block("SF Enc Verifier");
    printf("\n\n%d\n\n", SF_ct2.ct_g1.size());

    libff::print_header("SNARK Friendly Encryption 2");
    SF_ct_array.emplace_back(SF_ct2);

    // libff::enter_block("SF Encrypt");
    // for (int i = 1; i < 3; i++)
    // {
    //     SF_cypher_text<ppT> SF_ct = SF_encrypt(keypair,
    //                                            SF_key.pk,
    //                                            m, MSG_BLOCK,
    //                                            example.primary_input,
    //                                            example.auxiliary_input); // Create Enc Proof
    //     SF_ct_array.emplace_back(SF_ct);
    // }
    // libff::leave_block("SF Encrypt");

    libff::print_header("SNARK Friendly Decryption");

    libff::enter_block("SF Decrypt");
    SF_pt = SF_decrypt(keypair, SF_key.sk, SF_key.vk, SF_ct_array); // Create Dec proof
    libff::leave_block("SF Decrypt");

    libff::print_header("SNARK Friendly Decrypt Verifier");
    libff::enter_block("SF Dec Verifier");
    bool ans_dec = SF_dec_verifier(keypair, SF_key.pk, SF_key.vk, SF_pt, SF_ct_array); // Decryption Proof
    printf("* The dec verification result is: %s\n", (ans_dec ? "PASS" : "FAIL"));
    libff::leave_block("SF Dec Verifier");

    ans = ans_dec;

    std::cout << "\n\t* Decrypt message *" << std::endl;
    for (size_t i = 0; i < SF_pt.msg.size(); i++)
    {
        std::cout << "\t    [" << i << "] ";
        SF_pt.msg[i].print();
    }

    libff::leave_block("Call to run_r1cs_gg_ppzksnark");

    return (ans);
}

} // namespace libsnark

#endif // RUN_R1CS_GG_PPZKSNARK_TCC_
