#ifndef R1CS_HFAL_XP2_PPZKSNARK_TCC_
#define R1CS_HFAL_XP2_PPZKSNARK_TCC_

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
bool r1cs_HFAL_XP2_ppzksnark_pp<ppT>::operator==(const r1cs_HFAL_XP2_ppzksnark_pp<ppT> &other) const
{
    return (this->hfal_H == other.proof);
}

template <typename ppT>
std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_XP2_ppzksnark_pp<ppT> &pp)
{
    out << pp.hfal_H << OUTPUT_NEWLINE;

    return out;
}

template <typename ppT>
std::istream &operator>>(std::istream &in, r1cs_HFAL_XP2_ppzksnark_pp<ppT> &pp)
{
    in >> pp.hfal_H;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}
template <typename ppT>
bool r1cs_HFAL_XP2_ppzksnark_proving_key<ppT>::operator==(const r1cs_HFAL_XP2_ppzksnark_proving_key<ppT> &other) const
{
    return (this->F_g1 == other.F_g1 &&
            this->T_g1 == other.T_g1);
}
template <typename ppT>
std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_XP2_ppzksnark_proving_key<ppT> &pk)
{
    out << pk.F_g1 << OUTPUT_NEWLINE;
    out << pk.T_g1 << OUTPUT_NEWLINE;

    return out;
}
template <typename ppT>
std::istream &operator>>(std::istream &in, const r1cs_HFAL_XP2_ppzksnark_proving_key<ppT> &pk)
{
    in >> pk.F_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.T_g1;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template <typename ppT>
bool r1cs_HFAL_XP2_ppzksnark_verification_key<ppT>::operator==(const r1cs_HFAL_XP2_ppzksnark_verification_key<ppT> &other) const
{
    return (this->delta_g1 == other.delta_g1 &&
            this->k_g1 == other.k_g1);
}
template <typename ppT>
std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_XP2_ppzksnark_verification_key<ppT> &vk)
{
    out << vk.delta_g1 << OUTPUT_NEWLINE;
    out << vk.k_g1 << OUTPUT_NEWLINE;

    return out;
}
template <typename ppT>
std::istream &operator>>(std::istream &in, const r1cs_HFAL_XP2_ppzksnark_verification_key<ppT> &vk)
{
    in >> vk.delta_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.k_g1;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template <typename ppT>
bool r1cs_HFAL_XP2_ppzksnark_proof<ppT>::operator==(const r1cs_HFAL_XP2_ppzksnark_proof<ppT> &other) const
{
    return (this->proof == other.proof);
}

template <typename ppT>
std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_XP2_ppzksnark_proof<ppT> &proof)
{
    out << proof.proof << OUTPUT_NEWLINE;

    return out;
}

template <typename ppT>
std::istream &operator>>(std::istream &in, r1cs_HFAL_XP2_ppzksnark_proof<ppT> &proof)
{
    in >> proof.proof;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template <typename ppT>
r1cs_HFAL_XP2_ppzksnark_pp<ppT> r1cs_HFAL_XP2_ppzksnark_setup(const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input){
    
    libff::G1_vector<ppT> H_vector;
    H_vector.reserve(primary_input.size() + 1);

    for(size_t i = 0; i < primary_input.size() + 1; i++){
		//H_vector.emplace_back(libff::G1<ppT>::one());
		H_vector.emplace_back(libff::G1<ppT>::random_element());
    }
    r1cs_HFAL_XP2_ppzksnark_pp<ppT> pp = r1cs_HFAL_XP2_ppzksnark_pp<ppT>(std::move(H_vector));
	
	pp.print_size();

    return pp;
}

template <typename ppT>
r1cs_HFAL_XP2_ppzksnark_hash<ppT> r1cs_HFAL_XP2_ppzksnark_hashing(const r1cs_HFAL_XP2_ppzksnark_pp<ppT> &pp, const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input){

    libff::G1<ppT> sigma_g1 = libff::G1<ppT>::zero();
    sigma_g1 = pp.hfal_H[0];


    for(size_t i = 0; i < primary_input.size(); i++){
        sigma_g1 = primary_input[i] * pp.hfal_H[i+1] + sigma_g1;
    }
    r1cs_HFAL_XP2_ppzksnark_hash<ppT> hash = r1cs_HFAL_XP2_ppzksnark_hash<ppT>(std::move(sigma_g1));

	hash.print_size();

    return hash;
}

template <typename ppT>
r1cs_HFAL_XP2_ppzksnark_keypair<ppT> r1cs_HFAL_XP2_ppzksnark_generator(r1cs_HFAL_XP2_ppzksnark_pp<ppT> &pp, accumulation_vector<libff::G1<ppT> > &gamma_F){
    libff::Fr<ppT> delta = libff::Fr<ppT>::random_element();
    libff::Fr<ppT> kilo = libff::Fr<ppT>::random_element();

    libff::G1_vector<ppT> T_ekF;
    T_ekF.reserve(pp.hfal_H.size());

    T_ekF.emplace_back( (delta * gamma_F.first) + (kilo * pp.hfal_H[0]) );
    for(size_t i = 0; i < gamma_F.rest.values.size(); i++){
        T_ekF.emplace_back( (delta * gamma_F.rest.values[i])+(kilo * pp.hfal_H[i+1]) );
    }

    r1cs_HFAL_XP2_ppzksnark_proving_key<ppT> pk 
        = r1cs_HFAL_XP2_ppzksnark_proving_key<ppT>(std::move(gamma_F),std::move(T_ekF));
    r1cs_HFAL_XP2_ppzksnark_verification_key<ppT> vk 
        = r1cs_HFAL_XP2_ppzksnark_verification_key<ppT>(std::move(delta),std::move(kilo));
    
	pk.print_size();
	vk.print_size();

    return r1cs_HFAL_XP2_ppzksnark_keypair<ppT>(std::move(pp), std::move(pk), std::move(vk));

}

template <typename ppT>
r1cs_HFAL_XP2_ppzksnark_proof<ppT> r1cs_HFAL_XP2_ppzksnark_prover(const r1cs_HFAL_XP2_ppzksnark_proving_key<ppT> &pk, const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input, const accumulation_vector<libff::G1<ppT>> &ax){

    libff::G1<ppT> pi = libff::G1<ppT>::zero();
    pi = pk.T_g1[0];    
    for(size_t i = 0; i <  primary_input.size(); i++){ 
        pi = primary_input[i] * pk.T_g1[i+1] + pi;
    }

    r1cs_HFAL_XP2_ppzksnark_proof<ppT> proof
        = r1cs_HFAL_XP2_ppzksnark_proof<ppT>(std::move(pi));

	proof.print_size();

    return proof;
}

template <typename ppT>
bool r1cs_HFAL_XP2_ppzksnark_verifier(const r1cs_HFAL_XP2_ppzksnark_verification_key<ppT> &vk, 
                                    const r1cs_HFAL_XP2_ppzksnark_hash<ppT> &hash, 
                                    const accumulation_vector<libff::G1<ppT>> &ax, 
                                    const r1cs_HFAL_XP2_ppzksnark_proof<ppT> &proof){
	return ((proof.proof) == (vk.delta_g1 * ax.first) + (vk.k_g1 * hash.HASH));
}
}// libsnark

#endif
