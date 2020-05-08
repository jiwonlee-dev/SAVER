#ifndef R1CS_HFAL_XP1_PPZKSNARK_TCC_
#define R1CS_HFAL_XP1_PPZKSNARK_TCC_

#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <sstream>

#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <libsnark/knowledge_commitment/kc_multiexp.hpp>
#include <libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp>

namespace libsnark
{

template <typename ppT>
bool r1cs_HFAL_XP1_ppzksnark_pp<ppT>::operator==(const r1cs_HFAL_XP1_ppzksnark_pp<ppT> &other) const
{
    return (this->hfal_H == other.proof);
}

template <typename ppT>
std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_XP1_ppzksnark_pp<ppT> &pp)
{
    out << pp.hfal_H << OUTPUT_NEWLINE;

    return out;
}

template <typename ppT>
std::istream &operator>>(std::istream &in, r1cs_HFAL_XP1_ppzksnark_pp<ppT> &pp)
{
    in >> pp.hfal_H;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}
template <typename ppT>
bool r1cs_HFAL_XP1_ppzksnark_proving_key<ppT>::operator==(const r1cs_HFAL_XP1_ppzksnark_proving_key<ppT> &other) const
{
    return (this->F_g1 == other.F_g1 &&
            this->T_g1 == other.T_g1 &&
            this->R_g1 == other.R_g1);
}
template <typename ppT>
std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_XP1_ppzksnark_proving_key<ppT> &pk)
{
    out << pk.F_g1 << OUTPUT_NEWLINE;
    out << pk.T_g1 << OUTPUT_NEWLINE;
    out << pk.R_g1 << OUTPUT_NEWLINE;

    return out;
}
template <typename ppT>
std::istream &operator>>(std::istream &in, const r1cs_HFAL_XP1_ppzksnark_proving_key<ppT> &pk)
{
    in >> pk.F_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.T_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.R_g1;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template <typename ppT>
bool r1cs_HFAL_XP1_ppzksnark_verification_key<ppT>::operator==(const r1cs_HFAL_XP1_ppzksnark_verification_key<ppT> &other) const
{
    return (this->u_g2 == other.u_g2 &&
            this->v_g2 == other.v_g2 &&
            this->w_g2 == other.w_g2
            );
}
template <typename ppT>
std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_XP1_ppzksnark_verification_key<ppT> &vk)
{
    out << vk.u_g2 << OUTPUT_NEWLINE;
    out << vk.v_g2 << OUTPUT_NEWLINE;
    out << vk.w_g2 << OUTPUT_NEWLINE;

    return out;
}
template <typename ppT>
std::istream &operator>>(std::istream &in, const r1cs_HFAL_XP1_ppzksnark_verification_key<ppT> &vk)
{
    in >> vk.u_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.v_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.w_g2;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template <typename ppT>
bool r1cs_HFAL_XP1_ppzksnark_proof<ppT>::operator==(const r1cs_HFAL_XP1_ppzksnark_proof<ppT> &other) const
{
    return (this->T_sum_G1 == other.T_sum_G1 &&
            this->R_sum_G1 == other.R_sum_G1);
}

template <typename ppT>
std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_XP1_ppzksnark_proof<ppT> &proof)
{
    out << proof.T_sum_G1 << OUTPUT_NEWLINE;
    out << proof.R_sum_G1 << OUTPUT_NEWLINE;

    return out;
}

template <typename ppT>
std::istream &operator>>(std::istream &in, r1cs_HFAL_XP1_ppzksnark_proof<ppT> &proof)
{
    in >> proof.T_sum_G1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.R_sum_G1;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template <typename ppT>
r1cs_HFAL_XP1_ppzksnark_pp<ppT> r1cs_HFAL_XP1_ppzksnark_setup(const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input){
    
    libff::G1_vector<ppT> H_vector;
    H_vector.reserve(primary_input.size() + 1);

    for(size_t i = 0; i < primary_input.size() + 1; i++){
		//H_vector.emplace_back(libff::G1<ppT>::one());
		H_vector.emplace_back(libff::G1<ppT>::random_element());
    }
    r1cs_HFAL_XP1_ppzksnark_pp<ppT> pp = r1cs_HFAL_XP1_ppzksnark_pp<ppT>(std::move(H_vector));
	
	pp.print_size();

    return pp;
}

template <typename ppT>
r1cs_HFAL_XP1_ppzksnark_hash<ppT> r1cs_HFAL_XP1_ppzksnark_hashing(const r1cs_HFAL_XP1_ppzksnark_pp<ppT> &pp, const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input){

    libff::G1<ppT> sigma_g1 = libff::G1<ppT>::zero();
    sigma_g1 = pp.hfal_H[0];

    for(size_t i = 0; i < primary_input.size(); i++){
        sigma_g1 = primary_input[i] * pp.hfal_H[i+1] + sigma_g1;
    }
    r1cs_HFAL_XP1_ppzksnark_hash<ppT> hash = r1cs_HFAL_XP1_ppzksnark_hash<ppT>(std::move(sigma_g1));

	hash.print_size();

    return hash;
}

template <typename ppT>
r1cs_HFAL_XP1_ppzksnark_keypair<ppT> r1cs_HFAL_XP1_ppzksnark_generator(r1cs_HFAL_XP1_ppzksnark_pp<ppT> &pp, accumulation_vector<libff::G1<ppT> > &gamma_F){
    libff::Fr<ppT> u_fr = libff::Fr<ppT>::random_element();
    libff::Fr<ppT> v_fr = libff::Fr<ppT>::random_element();
    libff::Fr<ppT> w_fr = libff::Fr<ppT>::random_element();

    libff::G1_vector<ppT> T_g1_vect;
    libff::G1_vector<ppT> R_g1_vect;

    T_g1_vect.reserve(pp.hfal_H.size());
    R_g1_vect.reserve(pp.hfal_H.size());

    R_g1_vect.emplace_back( libff::G1<ppT>::random_element() );
    T_g1_vect.emplace_back( (u_fr * pp.hfal_H[0]) +
                            (v_fr * R_g1_vect[0]) +
                            (w_fr * gamma_F.first)
                            );
    for(size_t i = 0; i < gamma_F.rest.values.size(); i++){
        R_g1_vect.emplace_back( libff::G1<ppT>::random_element() );
        T_g1_vect.emplace_back( (u_fr * pp.hfal_H[i+1]) +
                                (v_fr * R_g1_vect[i+1]) +
                                (w_fr * gamma_F.rest.values[i])
                                );
    }

    r1cs_HFAL_XP1_ppzksnark_proving_key<ppT> pk 
        = r1cs_HFAL_XP1_ppzksnark_proving_key<ppT>( 
                                                    std::move(gamma_F), 
                                                    std::move(T_g1_vect), 
                                                    std::move(R_g1_vect)
                                                  );
    r1cs_HFAL_XP1_ppzksnark_verification_key<ppT> vk 
        = r1cs_HFAL_XP1_ppzksnark_verification_key<ppT>(
                                                        std::move(u_fr * libff::G2<ppT>::one()),
                                                        std::move(v_fr * libff::G2<ppT>::one()),
                                                        std::move(w_fr * libff::G2<ppT>::one())
                                                       );
    
	pk.print_size();
	vk.print_size();

    return r1cs_HFAL_XP1_ppzksnark_keypair<ppT>(std::move(pp), std::move(pk), std::move(vk));

}

template <typename ppT>
r1cs_HFAL_XP1_ppzksnark_proof<ppT> r1cs_HFAL_XP1_ppzksnark_prover(const r1cs_HFAL_XP1_ppzksnark_proving_key<ppT> &pk, const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input, const accumulation_vector<libff::G1<ppT>> &ax){
    libff::G1<ppT> T_sum = libff::G1<ppT>::zero();
    libff::G1<ppT> R_sum = libff::G1<ppT>::zero();
    T_sum = pk.T_g1[0];    
    R_sum = pk.R_g1[0];
    for(size_t i = 0; i <  primary_input.size(); i++){ 
        T_sum = primary_input[i] * pk.T_g1[i+1] + T_sum;
        R_sum = primary_input[i] * pk.R_g1[i+1] + R_sum;
    }

    r1cs_HFAL_XP1_ppzksnark_proof<ppT> proof
        = r1cs_HFAL_XP1_ppzksnark_proof<ppT>(std::move(T_sum), std::move(R_sum));

	proof.print_size();

    return proof;
}

template <typename ppT>
bool r1cs_HFAL_XP1_ppzksnark_verifier(const r1cs_HFAL_XP1_ppzksnark_verification_key<ppT> &vk, 
                                    const r1cs_HFAL_XP1_ppzksnark_hash<ppT> &hash, 
                                    const accumulation_vector<libff::G1<ppT>> &ax, 
                                    const r1cs_HFAL_XP1_ppzksnark_proof<ppT> &proof){
    const libff::G1_precomp<ppT> proof_g_T_precomp = ppT::precompute_G1(proof.T_sum_G1);
    const libff::G1_precomp<ppT> proof_g_R_precomp = ppT::precompute_G1(proof.R_sum_G1);
    const libff::G1_precomp<ppT> acc_precomp = ppT::precompute_G1(ax.first);

    const libff::G2_precomp<ppT> g2_one_precomp = ppT::precompute_G2(libff::G2<ppT>::one());
    const libff::G2_precomp<ppT> vk_v_g2_precomp = ppT::precompute_G2(vk.v_g2);
    const libff::G2_precomp<ppT> vk_w_g2_precomp = ppT::precompute_G2(vk.w_g2);

    libff::GT<ppT> vf_right_one = ppT::reduced_pairing( 
                                                        hash.HASH,
                                                        vk.u_g2
                                                      ); //e(sigma_x,U)

    libff::Fqk<ppT> QAP1 = ppT::miller_loop(proof_g_T_precomp, g2_one_precomp);
    libff::Fqk<ppT> QAP2 = ppT::double_miller_loop(
        proof_g_R_precomp, vk_v_g2_precomp,
        acc_precomp, vk_w_g2_precomp
    );

    libff::GT<ppT> QAP = ppT::final_exponentiation(QAP1 * QAP2.unitary_inverse());

    return (vf_right_one == QAP);
}
}// libsnark

#endif
