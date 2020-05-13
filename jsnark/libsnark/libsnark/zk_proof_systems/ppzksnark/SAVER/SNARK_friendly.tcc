/*******************************************************************************
 * Author: JaeKyoung Choi <cjk2889@kookmin.ac.kr>
 *******************************************************************************/

#ifndef SNARK_FRIENDLY_TCC_
#define SNARK_FRIENDLY_TCC_

#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <sstream>

#include <gmp.h>

#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <libsnark/knowledge_commitment/kc_multiexp.hpp>
#include <libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp>

namespace libsnark {
//SF_public_key
template<typename ppT>
bool SF_public_key<ppT>::operator==(const SF_public_key<ppT> &other) const
{
    return (this->delta_g1 == other.delta_g1 && 
            this->delta_s_g1 == other.delta_s_g1 && 
            this->t_g1 == other.t_g1 &&
            this->t_g2 == other.t_g2 &&
            this->delta_sum_s_g1 == other.delta_sum_s_g1 && 
            this->gamma_inverse_sum_s_g1 == other.gamma_inverse_sum_s_g1);
}
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_public_key<ppT> &pk)
{
    out << pk.delta_g1 << OUTPUT_NEWLINE;
    out << pk.delta_s_g1 << OUTPUT_NEWLINE;
    out << pk.t_g1 << OUTPUT_NEWLINE;
    out << pk.t_g2 << OUTPUT_NEWLINE;
    out << pk.delta_sum_s_g1 << OUTPUT_NEWLINE;
    out << pk.gamma_inverse_sum_s_g1 << OUTPUT_NEWLINE;
    return out;
}
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_public_key<ppT> &pk)
{
    in >> pk.delta_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.delta_s_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.t_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.t_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.delta_sum_s_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.gamma_inverse_sum_s_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}
//SF_secret_key
template<typename ppT>
bool SF_secret_key<ppT>::operator==(const SF_secret_key<ppT> &other) const
{
    return (this->rho == other.rho);
}
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_secret_key<ppT> &sk)
{
    out << sk.rho << OUTPUT_NEWLINE;

    return out;
}
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_secret_key<ppT> &sk)
{
    in >> sk.rho;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}
//SF_verify_key
template<typename ppT>
bool SF_verify_key<ppT>::operator==(const SF_verify_key<ppT> &other) const
{
    return (this->rho_g2 == other.rho_g2 && 
            this->rho_sv_g2 == other.rho_sv_g2 && 
            this->rho_rhov_g2 == other.rho_rhov_g2);
}
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_verify_key<ppT> &vk)
{
    out << vk.rho_g2 << OUTPUT_NEWLINE;
    out << vk.rho_sv_g2 << OUTPUT_NEWLINE;
    out << vk.rho_rhov_g2 << OUTPUT_NEWLINE;
    return out;
}
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_verify_key<ppT> &vk)
{
    in >> vk.rho_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.rho_sv_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.rho_rhov_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}
//SF_keypair
template<typename ppT>
bool SF_keypair<ppT>::operator==(const SF_keypair<ppT> &other) const
{
    return (this->pk == other.pk &&
            this->sk == other.sk &&
            this->vk == other.vk );
}
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_keypair<ppT> &keypair)
{
    out << keypair.pk;
    out << keypair.sk;
    out << keypair.vk;
    return out;
}
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_keypair<ppT> &keypair)
{
    in >> keypair.pk;
    in >> keypair.sk;
    in >> keypair.vk;
    return in;
}
//SF_cypher_text
template<typename ppT>
bool SF_cypher_text<ppT>::operator==(const SF_cypher_text<ppT> &other) const
{
    return (this->proof == other.proof &&
            this->ct_g1 == other.ct_g1 &&
            this->primary_input == other.primary_input);
}
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_cypher_text<ppT> &ct)
{
    out << ct.proof << OUTPUT_NEWLINE;
    out << ct.ct_g1 << OUTPUT_NEWLINE;
    out << ct.primary_input << OUTPUT_NEWLINE;

    return out;
}
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_cypher_text<ppT> &ct)
{
    in >> ct.proof;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> ct.ct_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> ct.primary_input;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}
//SF_plain_text
template<typename ppT>
bool SF_plain_text<ppT>::operator==(const SF_plain_text<ppT> &other) const
{
    return (this->msg == other.msg &&
            this->vm == other.vm);
}
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_plain_text<ppT> &pt)
{
    out << pt.msg << OUTPUT_NEWLINE;
    out << pt.vm << OUTPUT_NEWLINE;
    return out;
}
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_plain_text<ppT> &pt)
{
    in >> pt.msg;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pt.vm;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}
// end stream

template <typename ppT>
SF_keypair<ppT> SF_key_generator(const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair,const size_t massage_size){
    const size_t input_size = gg_keypair.vk.gamma_ABC_g1.rest.values.size();

    libff::Fr<ppT> rho = libff::Fr<ppT>::random_element();
    libff::Fr<ppT> s_sum = libff::Fr<ppT>::zero();

    libff::G1<ppT> delta_g1 = gg_keypair.vk.delta_g1;
    libff::G1_vector<ppT> delta_s_g1;
    libff::G1<ppT> delta_sum_s_g1;
    libff::G1<ppT> gamma_inverse_sum_s_g1 = gg_keypair.vk.gamma_g1;

    libff::G2<ppT> rho_g2 = rho * libff::G2<ppT>::one();
    libff::G2_vector<ppT> rho_sv_g2;
    libff::G2_vector<ppT> rho_rhov_g2;

    libff::G1_vector<ppT> t_g1;
    libff::G2_vector<ppT> t_g2;

    delta_s_g1.reserve(input_size);
    rho_sv_g2.reserve(input_size);
    rho_rhov_g2.reserve(input_size);
    t_g1.reserve(input_size);
    t_g2.reserve(input_size+1);
    
    libff::Fr<ppT> t = libff::Fr<ppT>::random_element();
    t_g2.emplace_back(t*libff::G2<ppT>::one());
    delta_sum_s_g1 = t*delta_g1;

    for(size_t i = 1; i < massage_size+1; i++){
        libff::Fr<ppT> s = libff::Fr<ppT>::random_element();
        libff::Fr<ppT> v = libff::Fr<ppT>::random_element();
        libff::Fr<ppT> sv = s*v;
        t = libff::Fr<ppT>::random_element();

        delta_s_g1.emplace_back(s*delta_g1);
        t_g1.emplace_back(t * gg_keypair.vk.gamma_ABC_g1.rest.values[i]);
        t_g2.emplace_back(t * libff::G2<ppT>::one());
        delta_sum_s_g1 = delta_sum_s_g1 + (s*t) * delta_g1;
        gamma_inverse_sum_s_g1 = gamma_inverse_sum_s_g1 + s*gg_keypair.vk.gamma_g1;

        rho_sv_g2.emplace_back(sv*libff::G2<ppT>::one());
        rho_rhov_g2.emplace_back(v*rho_g2);
    }
    gamma_inverse_sum_s_g1 = -gamma_inverse_sum_s_g1;
    SF_public_key<ppT> pk = SF_public_key<ppT>(delta_g1, delta_s_g1, t_g1, t_g2, delta_sum_s_g1, gamma_inverse_sum_s_g1);
    SF_secret_key<ppT> sk = SF_secret_key<ppT>( rho );
    SF_verify_key<ppT> vk = SF_verify_key<ppT> ( rho_g2, rho_sv_g2, rho_rhov_g2);
    SF_keypair<ppT> sf_keyset = SF_keypair<ppT>( pk, sk, vk);

    return sf_keyset;
}

template <typename ppT>
SF_cypher_text<ppT> SF_encrypt( const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair, 
                                const SF_public_key<ppT> &pk,
                                const std::string msg, const size_t massage_size,
                                const r1cs_gg_ppzksnark_primary_input<ppT> &r1cs_primary_input,
                                const r1cs_gg_ppzksnark_auxiliary_input<ppT> &auxiliary_input){
    const size_t input_size = gg_keypair.vk.gamma_ABC_g1.rest.values.size();


    //libff::Fr<ppT> r = libff::Fr<ppT>::one();
    libff::Fr<ppT> r = libff::Fr<ppT>::random_element();

    r1cs_gg_ppzksnark_primary_input<ppT> primary_input;
    libff::G1_vector<ppT> ct_g1;

    primary_input.reserve(input_size);
    ct_g1.reserve(massage_size+2);

    primary_input.emplace_back( libff::Fr<ppT>::one() );
    ct_g1.emplace_back( r*pk.delta_g1 );

    libff::G1<ppT> sum_tm_g1 = r*pk.delta_sum_s_g1;

    for(size_t i = 0; i < msg.length(); i = i+8){
        unsigned int msg_hex = 0;
        for(size_t j = 0; j < 8; j++){
            msg_hex *= 16;
            msg_hex += (msg.at(i+j) >= 'A') ? (msg.at(i+j) - 'A' + 10) : (msg.at(i+j) - '0');
        }

        primary_input.emplace_back(libff::Fr<ppT>(msg_hex));
        ct_g1.emplace_back( r*pk.delta_s_g1[i/8]
                        + libff::Fr<ppT>(msg_hex) * gg_keypair.vk.gamma_ABC_g1.rest.values[(i/8)+1] );
        sum_tm_g1 = sum_tm_g1 + libff::Fr<ppT>(msg_hex) * pk.t_g1[(i/8)];
    }
    ct_g1.emplace_back(sum_tm_g1);

    libff::Fr_vector<ppT> remaining_input;
    remaining_input.reserve( r1cs_primary_input.size() - massage_size);

    for(size_t i = massage_size + 1; i < r1cs_primary_input.size();i++){
        primary_input.emplace_back(r1cs_primary_input[i]);
        remaining_input.emplace_back(r1cs_primary_input[i]);
        // printf("::: %d :: ",i);
        // r1cs_primary_input[i].print();
    }
        std::string encpath = "./prove" ; encpath += std::to_string(massage_size); encpath += ".txt";

        libff::enter_block("gg Enc");
    r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(gg_keypair.pk, primary_input, auxiliary_input);
        libff::leave_block("gg Enc");
    proof.g_C = proof.g_C + r*pk.gamma_inverse_sum_s_g1;

    SF_cypher_text<ppT> CT(proof,ct_g1,remaining_input);

    return CT;
}

template <typename ppT>
SF_plain_text<ppT> SF_decrypt( const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair, 
                        const SF_secret_key<ppT> &sk,
                        const SF_verify_key<ppT> &vk,
                        const vector<SF_cypher_text<ppT>> &ct){
                         
    libff::G1<ppT> C0_new = libff::G1<ppT>::zero();
    libff::Fr_vector<ppT> m_new;
    m_new.reserve(ct[0].ct_g1.size() - 2);

    for(size_t i = 0; i < ct[0].ct_g1.size() - 2; i++)
        m_new.emplace_back(libff::Fr<ppT>::zero());

    for(size_t i = 0; i < ct.size(); i++){
        std::string msg = "";
        for(size_t j = 1; j < ct[i].ct_g1.size() - 1; j++){
            libff::GT<ppT> ci_sk_0 = ppT::reduced_pairing(
                ct[i].ct_g1[j], 
                vk.rho_rhov_g2[j-1]);
            libff::GT<ppT> c0_sk_i = ppT::reduced_pairing(
                ct[i].ct_g1[0], 
                vk.rho_sv_g2[j-1]) ^ sk.rho;
            libff::GT<ppT> dec_tmp = ci_sk_0 * c0_sk_i.unitary_inverse();
            libff::GT<ppT> discrete_log = libff::GT<ppT>::one();
            libff::GT<ppT> bruteforce = ppT::reduced_pairing(
                        gg_keypair.vk.gamma_ABC_g1.rest.values[j],
                        vk.rho_rhov_g2[j - 1]);
            for(size_t k = 0; k < 10001; k++){
                bool ck = false;
                for(size_t l = 0; l < 65535; l++){
                    if(dec_tmp == discrete_log){
                        ck = true;
                        m_new[j-1] = m_new[j-1] + libff::Fr<ppT>(k*65535 + l);
                        break;
                    }
                    discrete_log = discrete_log * bruteforce;
                }
                if(ck == true){
                    break;
                }
            }
        }
        C0_new = C0_new + ct[i].ct_g1[0];
    }
    std::cout << "C_new ::: "; C0_new.print();

    libff::G1<ppT> verify_c0 = sk.rho * C0_new;

    SF_plain_text<ppT> pt = SF_plain_text<ppT>(m_new,verify_c0);

    return pt;
}

template <typename ppT>
bool SF_enc_verifier(       const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair,
                            const SF_public_key<ppT> &pk,
                            const SF_cypher_text<ppT> &ct){
    const size_t input_size = gg_keypair.vk.gamma_ABC_g1.rest.values.size();
    size_t i = 0;

    libff::G1<ppT> acc = gg_keypair.vk.gamma_ABC_g1.first + gg_keypair.vk.gamma_ABC_g1.rest.values[0] + ct.ct_g1[0];
    libff::G1<ppT> test = libff::G1<ppT>::zero();
    libff::GT<ppT> sum_cipher = ppT::reduced_pairing(ct.ct_g1[0], pk.t_g2[0]);

    for(i = 1; i < ct.ct_g1.size()-1; i++){
        acc = acc + ct.ct_g1[i];
        sum_cipher = sum_cipher * ppT::reduced_pairing(ct.ct_g1[i], pk.t_g2[i]);
    }
    for(i = ct.ct_g1.size()-1; i < input_size; i++){
        //acc = acc + r1cs_primary_input[i] * gg_keypair.vk.gamma_ABC_g1.rest.values[i];
        acc = acc + ct.primary_input[i-ct.ct_g1.size()+1] * gg_keypair.vk.gamma_ABC_g1.rest.values[i];
        // printf("::: %d:%d :: ",i,i-ct.ct_g1.size()+1);
        // r1cs_primary_input[i].print();
    }
    libff::GT<ppT> presum_cipher = ppT::reduced_pairing(ct.ct_g1[ct.ct_g1.size()-1], libff::G2<ppT>::one());
    bool ans1 = (sum_cipher == presum_cipher);

    const libff::G1_precomp<ppT> proof_g1_A_precomp = ppT::precompute_G1(ct.proof.g_A);
    const libff::G2_precomp<ppT> proof_g2_B_precomp = ppT::precompute_G2(ct.proof.g_B);

    const libff::G1_precomp<ppT> pk_g1_alpha_precomp = ppT::precompute_G1(gg_keypair.pk.alpha_g1);
    const libff::G2_precomp<ppT> pk_g2_beta_precomp = ppT::precompute_G2(gg_keypair.pk.beta_g2);

    const libff::G1_precomp<ppT> proof_g1_C_precomp = ppT::precompute_G1(ct.proof.g_C);
    const libff::G2_precomp<ppT> vk_g2_delta_precomp = ppT::precompute_G2(gg_keypair.vk.delta_g2);

    const libff::G1_precomp<ppT> proof_g1_cn_precomp = ppT::precompute_G1(acc);
    const libff::G2_precomp<ppT> vk_g2_gamma_precomp = ppT::precompute_G2(gg_keypair.vk.gamma_g2);

    
    libff::Fqk<ppT> QAPl_1 = ppT::miller_loop(proof_g1_A_precomp, proof_g2_B_precomp);
    libff::Fqk<ppT> QAPl_2 = ppT::double_miller_loop(
        proof_g1_C_precomp, vk_g2_delta_precomp,
        pk_g1_alpha_precomp, pk_g2_beta_precomp
        );

    libff::Fqk<ppT> QAPr_2 = ppT::miller_loop(proof_g1_cn_precomp, vk_g2_gamma_precomp); 

    libff::GT<ppT> QAPl = ppT::final_exponentiation(QAPl_1 * QAPl_2.unitary_inverse());
    libff::GT<ppT> QAPr = ppT::final_exponentiation(QAPr_2);

    bool ans2 = (QAPl == QAPr);

    std::cout << "ans1 " << ans1 << std::endl;
    std::cout << "ans2 " << ans2 << std::endl;

    return (ans1 && ans2);
}

template <typename ppT>
bool SF_dec_verifier(const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair,
                     const SF_public_key<ppT> &pk,
                     const SF_verify_key<ppT> &vk,
                     const SF_plain_text<ppT> &pt,
                     const vector<SF_cypher_text<ppT>> &ct){
    libff::G1_vector<ppT> new_ct_g1;
    new_ct_g1.reserve(ct[0].ct_g1.size());
    for(size_t i = 0; i < ct[0].ct_g1.size(); i++)
        new_ct_g1.emplace_back(ct[0].ct_g1[i]);
    for(size_t i = 1; i < ct.size(); i++)
        for(size_t j = 0; j < ct[i].ct_g1.size(); j++)
            new_ct_g1[j] = new_ct_g1[j] + ct[i].ct_g1[j];
    libff::GT<ppT> vm_gt = ppT::reduced_pairing(
        pt.vm,
        libff::G2<ppT>::one());
    libff::GT<ppT> new_c0_v0_gt = ppT::reduced_pairing(
        new_ct_g1[0],
        vk.rho_g2);
    bool ans1 = (vm_gt == new_c0_v0_gt);
    std::cout << "ans1 " << ans1 << std::endl;

    for(size_t i = 1; i < new_ct_g1.size()-1; i++){
        libff::GT<ppT> ci_v_nj_gt = ppT::reduced_pairing(
            new_ct_g1[i],
            vk.rho_rhov_g2[i - 1]);
        libff::GT<ppT> v_vj_gt = ppT::reduced_pairing(
            pt.vm,
            vk.rho_sv_g2[i - 1]);
        libff::GT<ppT> verify_tmp = ci_v_nj_gt * v_vj_gt.unitary_inverse();
        libff::GT<ppT> verify_msg = ppT::reduced_pairing(
            gg_keypair.vk.gamma_ABC_g1.rest.values[i],
            vk.rho_rhov_g2[i - 1])^pt.msg[i-1];
        printf("msg[%d]:: ",i);
        pt.msg[i-1].print();
        if(verify_tmp != verify_msg){
            std::cout << "\tF A I L [ " << i << " ]"<< std::endl;
            return false;
        }
    }

    return (ans1);
}

template <typename ppT>
SF_cypher_text<ppT> SF_rerandomize(const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair,
                                    const SF_public_key<ppT> &pk,
                                    const SF_cypher_text<ppT> &ct){
    libff::G1_vector<ppT> ct_g1;

    ct_g1.reserve(ct.ct_g1.size());

    libff::Fr<ppT> r = libff::Fr<ppT>::random_element();
    libff::Fr<ppT> z1 = libff::Fr<ppT>::random_element();
    libff::Fr<ppT> z2 = libff::Fr<ppT>::random_element();

    // libff::Fr<ppT> r = libff::Fr<ppT>::one();
    // libff::Fr<ppT> z1 = libff::Fr<ppT>::one();
    // libff::Fr<ppT> z2 = libff::Fr<ppT>::one();
    
    libff::Fr<ppT> z1_inverse = z1.inverse();

    ct_g1.emplace_back(ct.ct_g1[0] + r * pk.delta_g1);
    for(size_t i = 1; i < ct.ct_g1.size()-1; i++){
        ct_g1.emplace_back(ct.ct_g1[i] + r * pk.delta_s_g1[i-1]);
    }
    ct_g1.emplace_back(ct.ct_g1[ct.ct_g1.size()-1] + r * pk.delta_sum_s_g1);

    libff::G1<ppT> g1_A = z1 * ct.proof.g_A;
    libff::G2<ppT> g2_B = z1_inverse * ct.proof.g_B + z2 * gg_keypair.vk.delta_g2;
    libff::G1<ppT> g1_C = ct.proof.g_C + z2 * g1_A + r * pk.gamma_inverse_sum_s_g1;
    
    r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_proof<ppT>(std::move(g1_A), std::move(g2_B), std::move(g1_C));
    
    libff::Fr_vector<ppT> remaining_input = std::move(ct.primary_input);
    SF_cypher_text<ppT> CT(proof,ct_g1,remaining_input);
    
    return CT;
}

}

#endif
