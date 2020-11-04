/*******************************************************************************
 * Author: JaeKyoung Choi <cjk2889@kookmin.ac.kr>
 *******************************************************************************/

#ifndef SNARK_FRIENDLY_HPP_
#define SNARK_FRIENDLY_HPP_

#include <memory>

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/common/data_structures/accumulation_vector.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/SAVER/r1cs_gg_ppzksnark_params.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/SAVER/r1cs_gg_ppzksnark.hpp>

namespace libsnark {

template<typename ppT>
class SF_public_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_public_key<ppT> &pk);

template<typename ppT>
std::istream& operator>>(std::istream &in, SF_public_key<ppT> &pk);

template<typename ppT>
class SF_public_key{
public:
    libff::G1<ppT> delta_g1;
    libff::G1_vector<ppT> delta_s_g1;
    libff::G1_vector<ppT> t_g1;
    libff::G2_vector<ppT> t_g2;
    libff::G1<ppT> delta_sum_s_g1;
    libff::G1<ppT> gamma_inverse_sum_s_g1;

    SF_public_key() {};
    SF_public_key<ppT>& operator=(const SF_public_key<ppT> &other) = default;
    SF_public_key(const SF_public_key<ppT> &other) = default;
    SF_public_key(SF_public_key<ppT> &&other) = default;
    SF_public_key(libff::G1<ppT> &delta_g1,
                  libff::G1_vector<ppT> &delta_s_g1,
                  libff::G1_vector<ppT> &t_g1,
                  libff::G2_vector<ppT> &t_g2,
                  libff::G1<ppT> &delta_sum_s_g1,
                  libff::G1<ppT> &gamma_inverse_sum_s_g1) :
        delta_g1(delta_g1),
        delta_s_g1(delta_s_g1),
        t_g1(t_g1),
        t_g2(t_g2),
        delta_sum_s_g1(delta_sum_s_g1),
        gamma_inverse_sum_s_g1(gamma_inverse_sum_s_g1)
    {};

    size_t size_in_bits() const
    {
        return (libff::G1<ppT>::size_in_bits());
    }

    void print_size() const
    {
        libff::print_indent(); printf("* SF_PK size in bits: %zu\n",this->size_in_bits);
    }
    bool operator==(const SF_public_key<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const SF_public_key<ppT> &pk);
    friend std::istream& operator>> <ppT>(std::istream &in, SF_public_key<ppT> &pk);
};

template<typename ppT>
class SF_secret_key;
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_secret_key<ppT> &sk);
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_secret_key<ppT> &sk);

template<typename ppT>
class SF_secret_key{
public:
    libff::Fr<ppT> rho;

    SF_secret_key() {};
    SF_secret_key<ppT>& operator=(const SF_secret_key<ppT> &other) = default;
    SF_secret_key(const SF_secret_key<ppT> &other) = default;
    SF_secret_key(SF_secret_key<ppT> &&other) = default;
    SF_secret_key(
                    libff::Fr<ppT> &rho) :
        rho(rho)
    {};

    size_t size_in_bits() const
    {
        return (libff::Fr<ppT>::size_in_bits());
    }

    void print_size() const
    {
        libff::print_indent(); printf("* SF_SK size in bits: %zu\n",this->size_in_bits);
    }
    bool operator==(const SF_secret_key<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const SF_secret_key<ppT> &sk);
    friend std::istream& operator>> <ppT>(std::istream &in, SF_secret_key<ppT> &sk);
};

template<typename ppT>
class SF_verify_key;
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_verify_key<ppT> &vk);
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_verify_key<ppT> &vk);

template<typename ppT>
class SF_verify_key{
public:
    libff::G2<ppT> rho_g2;
    libff::G2_vector<ppT> rho_sv_g2;
    libff::G2_vector<ppT> rho_rhov_g2;

    SF_verify_key() {};
    SF_verify_key<ppT>& operator=(const SF_verify_key<ppT> &other) = default;
    SF_verify_key(const SF_verify_key<ppT> &other) = default;
    SF_verify_key(SF_verify_key<ppT> &&other) = default;
    SF_verify_key(libff::G2<ppT> &rho_g2,
                      libff::G2_vector<ppT> &rho_sv_g2,
                      libff::G2_vector<ppT> &rho_rhov_g2) :
        rho_g2(rho_g2),
        rho_sv_g2(rho_sv_g2),
        rho_rhov_g2(rho_rhov_g2)
    {};

    size_t size_in_bits() const
    {
        return (1 * libff::G2<ppT>::size_in_bits());
    }

    void print_size() const
    {
        libff::print_indent(); printf("* SF_VK size in bits: %zu\n",this->size_in_bits);
    }
    bool operator==(const SF_verify_key<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const SF_verify_key<ppT> &vk);
    friend std::istream& operator>> <ppT>(std::istream &in, SF_verify_key<ppT> &vk);
};

template<typename ppT>
class SF_keypair;

template<typename ppT>
std::ostream& operator<< (std::ostream& out,const SF_keypair<ppT> &keypair);

template<typename ppT>
std::istream& operator>> (std::istream& in,const SF_keypair<ppT> &keyapir); 

template<typename ppT>
class SF_keypair{
public:
    SF_public_key<ppT> pk;
    SF_secret_key<ppT> sk;
    SF_verify_key<ppT> vk;

    SF_keypair() = default;
    SF_keypair(const SF_keypair<ppT> &other) = default;
    SF_keypair( SF_public_key<ppT> &pk,
                SF_secret_key<ppT> &sk,
                SF_verify_key<ppT> &vk) :
        pk(std::move(pk)),
        sk(std::move(sk)),
        vk(std::move(vk))
    {}

    SF_keypair<ppT>& operator=(const SF_keypair<ppT>& src){
        if (this == &src) return *this;
        pk = src.pk; sk = src.sk; vk = src.vk;
        return *this;
    }
    bool operator==(const SF_keypair<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream& out,const SF_keypair<ppT> &keypair); //check
    friend std::istream& operator>> <ppT>(std::istream& in,const SF_keypair<ppT> &keyapir); 
    SF_keypair(SF_keypair<ppT> &&other) = default;
};

template<typename ppT>
class SF_cypher_text;
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_cypher_text<ppT> &ct);
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_cypher_text<ppT> &ct);

template<typename ppT>
class SF_cypher_text{
public:
    r1cs_gg_ppzksnark_proof<ppT> proof;
    libff::G1_vector<ppT> ct_g1;
    libff::Fr_vector<ppT> primary_input;
    
    SF_cypher_text() {};
    SF_cypher_text<ppT>& operator=(const SF_cypher_text<ppT> &other) = default;
    SF_cypher_text(const SF_cypher_text<ppT> &other) = default;
    SF_cypher_text(SF_cypher_text<ppT> &&other) = default;
    SF_cypher_text(
                    r1cs_gg_ppzksnark_proof<ppT> &proof,
                    libff::G1_vector<ppT> &ct_g1,
                    libff::Fr_vector<ppT> &primary_input ) :
        proof(std::move(proof)),
        ct_g1(std::move(ct_g1)),
        primary_input(std::move(primary_input))
    {};

    size_t size_in_bits() const
    {
        return (proof.size_in_bits()) + (libff::size_in_bits(ct_g1));
    }

    void print_size() const
    {
        libff::print_indent(); printf("* SF_CT size in bits: %zu\n",this->size_in_bits);
    }
    bool operator==(const SF_cypher_text<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const SF_cypher_text<ppT> &ct);
    friend std::istream& operator>> <ppT>(std::istream &in, SF_cypher_text<ppT> &ct);
};

template<typename ppT>
class SF_plain_text;
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_plain_text<ppT> &pt);
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_plain_text<ppT> &pt);

template<typename ppT>
class SF_plain_text{
public:
    libff::Fr_vector<ppT> msg;
    libff::G1<ppT> vm;

    SF_plain_text() {};
    SF_plain_text<ppT>& operator=(const SF_plain_text<ppT> &other) = default;
    SF_plain_text(const SF_plain_text<ppT> &other) = default;
    SF_plain_text(SF_plain_text<ppT> &&other) = default;
    SF_plain_text(
                        libff::Fr_vector<ppT> &msg,
                        libff::G1<ppT> &vm ) :
        msg(std::move(msg)),
        vm(std::move(vm))
    {};

    size_t size_in_bits() const
    {
        return (msg.size_in_bits()) + libff::G1<ppT>::size_in_bits();
    }

    void print_size() const
    {
        libff::print_indent(); printf("* SF_CT size in bits: %zu\n",this->size_in_bits);
    }
    bool operator==(const SF_plain_text<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const SF_plain_text<ppT> &pt);
    friend std::istream& operator>> <ppT>(std::istream &in, SF_plain_text<ppT> &pt);
};

template <typename ppT>
SF_keypair<ppT> SF_key_generator(const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair,const size_t massage_size);

template <typename ppT>
SF_cypher_text<ppT> SF_encrypt( const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair, 
                                const SF_public_key<ppT> &pk,
                                const std::string msg, const size_t massage_size,
                                const r1cs_gg_ppzksnark_primary_input<ppT> &r1cs_primary_input,
                                const r1cs_gg_ppzksnark_auxiliary_input<ppT> &auxiliary_input);

template <typename ppT>
SF_plain_text<ppT> SF_decrypt(  const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair, 
                                const SF_secret_key<ppT> &sk,
                                const SF_verify_key<ppT> &vk,
                                const vector<SF_cypher_text<ppT>> &ct);

template <typename ppT>
bool SF_enc_verifier(const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair,
                            const SF_public_key<ppT> &pk,
                            const SF_cypher_text<ppT> &ct);     
                                           
template <typename ppT>
bool SF_dec_verifier(const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair,
                     const SF_public_key<ppT> &pk,
                     const SF_verify_key<ppT> &vk,
                     const SF_plain_text<ppT> &pt,
                     const vector<SF_cypher_text<ppT>> &ct_vect);
template <typename ppT>
SF_cypher_text<ppT> SF_rerandomize(const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair,
                                    const SF_public_key<ppT> &pk,
                                    const SF_cypher_text<ppT> &ct);
}
#include <libsnark/zk_proof_systems/ppzksnark/SAVER/SNARK_friendly.tcc>
#endif