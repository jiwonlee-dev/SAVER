#ifndef R1CS_HFAL_PPZKSANRK_HPP_
#define R1CS_HFAL_PPZKSNARK_HPP_

#include <memory>

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/common/data_structures/accumulation_vector.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_HFAL_ppzksnark/r1cs_gg_ppzksnark_params.hpp>

namespace libsnark{

	template <typename ppT>
	class r1cs_HFAL_ppzksnark_pp;

	template <typename ppT>
	std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_ppzksnark_pp<ppT> &pp);

	template <typename ppT>
	std::istream &operator>>(std::istream &in, r1cs_HFAL_ppzksnark_pp<ppT> &pp);
	
	template<typename ppT>
	class r1cs_HFAL_ppzksnark_pp{
	public:
    	libff::G1_vector<ppT> hfal_H;

		r1cs_HFAL_ppzksnark_pp() {};
    	r1cs_HFAL_ppzksnark_pp<ppT>& operator=(const r1cs_HFAL_ppzksnark_pp<ppT> &other) = default;
		r1cs_HFAL_ppzksnark_pp(	const libff::G1_vector<ppT> &hfal_H) :
			hfal_H(hfal_H)
		{};

		size_t hfal_H_size() const
		{
			return hfal_H.size();
		}
		size_t size_in_bits() const
		{
			return libff::size_in_bits(hfal_H);
		}
		void print_size() const
		{
			libff::print_indent(); printf("* XP2 PP size in bits: %zu\n",this->size_in_bits());
		}
		bool operator==(const r1cs_HFAL_ppzksnark_pp<ppT> &other) const;
		friend std::ostream &operator<<<ppT>(std::ostream &out, const r1cs_HFAL_ppzksnark_pp<ppT> &pp);
		friend std::istream &operator>><ppT>(std::istream &in, r1cs_HFAL_ppzksnark_pp<ppT> &pp);
	};

	template <typename ppT>
	class r1cs_HFAL_ppzksnark_proving_key;

	template <typename ppT>
	std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_ppzksnark_proving_key<ppT> &pk);

	template <typename ppT>
	std::istream &operator>>(std::istream &in, r1cs_HFAL_ppzksnark_proving_key<ppT> &pk);

	template <typename ppT>
	class r1cs_HFAL_ppzksnark_proving_key{
	public:
    	accumulation_vector<libff::G1<ppT> > F_g1;
		libff::G1_vector<ppT> T_g1;

		r1cs_HFAL_ppzksnark_proving_key(){};
		r1cs_HFAL_ppzksnark_proving_key<ppT> &operator=(const r1cs_HFAL_ppzksnark_proving_key<ppT> &other) = default;
		r1cs_HFAL_ppzksnark_proving_key(const r1cs_HFAL_ppzksnark_proving_key<ppT> &other) = default;
		r1cs_HFAL_ppzksnark_proving_key(r1cs_HFAL_ppzksnark_proving_key<ppT> &&other) = default;
		r1cs_HFAL_ppzksnark_proving_key(const accumulation_vector<libff::G1<ppT>> &F_g1,
										const libff::G1_vector<ppT> &T_g1) : F_g1(F_g1),
																			T_g1(T_g1){};

		size_t F_g1_size_in_bits() const
		{
			return F_g1.size()*libff::G1<ppT>::size_in_bits();
		}
		size_t T_g1_size_in_bits() const
		{
			return T_g1.size()*libff::G1<ppT>::size_in_bits();
		}
		size_t size_in_bits() const
		{
			return F_g1.size_in_bits() + libff::size_in_bits(T_g1);
		}
		void print_size() const
		{
			libff::print_indent(); printf("* XP2 PK size in bits: %zu\n",this->size_in_bits());
		}

    	bool operator==(const r1cs_HFAL_ppzksnark_proving_key<ppT> &other) const;
    	friend std::ostream& operator<< <ppT>(std::ostream &out, const r1cs_HFAL_ppzksnark_proving_key<ppT> &pk);
    	friend std::istream& operator>> <ppT>(std::istream &in, r1cs_HFAL_ppzksnark_proving_key<ppT> &pk);
	};

	template <typename ppT>
	class r1cs_HFAL_ppzksnark_verification_key;

	template <typename ppT>
	std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_ppzksnark_verification_key<ppT> &vk);

	template <typename ppT>
	std::istream &operator>>(std::istream &in, r1cs_HFAL_ppzksnark_verification_key<ppT> &vk);

	template <typename ppT>
	class r1cs_HFAL_ppzksnark_verification_key{
	public:
    	libff::Fr<ppT> delta_g1;
		libff::Fr<ppT> k_g1;

		r1cs_HFAL_ppzksnark_verification_key() = default;
		r1cs_HFAL_ppzksnark_verification_key(const libff::Fr<ppT> delta_g1,
										const libff::Fr<ppT> k_g1) :
			delta_g1(delta_g1),
			k_g1(k_g1)	
		{};

		size_t delta_g1_size() const
		{
			return 1;
		}
		size_t k_g1_size() const
		{
			return 1;
		}
		size_t size_in_bits() const
		{
			return delta_g1_size() * libff::Fr<ppT>::size_in_bits() + k_g1_size() * libff::Fr<ppT>::size_in_bits();
		}
		void print_size() const
		{
			libff::print_indent(); printf("* XP2 VK size in bits: %zu\n",this->size_in_bits());
		}
    	bool operator==(const r1cs_HFAL_ppzksnark_verification_key<ppT> &other) const;
    	friend std::ostream& operator<< <ppT>(std::ostream &out, const r1cs_HFAL_ppzksnark_verification_key<ppT> &pk);
    	friend std::istream& operator>> <ppT>(std::istream &in, r1cs_HFAL_ppzksnark_verification_key<ppT> &pk);
	};

	template <typename ppT>
	class r1cs_HFAL_ppzksnark_keypair;

	template <typename ppT>
	std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_ppzksnark_keypair<ppT> &KEYPAIR);

	template <typename ppT>
	std::istream &operator>>(std::istream &in, r1cs_HFAL_ppzksnark_keypair<ppT> &KEYPAIR);
	
	template <typename ppT>
	class r1cs_HFAL_ppzksnark_keypair
	{
	  public:
	  	r1cs_HFAL_ppzksnark_pp<ppT> pp;
		r1cs_HFAL_ppzksnark_proving_key<ppT> pk;
		r1cs_HFAL_ppzksnark_verification_key<ppT> vk;

		r1cs_HFAL_ppzksnark_keypair(const r1cs_HFAL_ppzksnark_keypair<ppT> &other):
			pp(std::move(other.pp)),
			pk(std::move(other.pk)),
			vk(std::move(other.vk))
		{};
		r1cs_HFAL_ppzksnark_keypair(r1cs_HFAL_ppzksnark_pp<ppT> &&pp,
									r1cs_HFAL_ppzksnark_proving_key<ppT> &&pk,
									r1cs_HFAL_ppzksnark_verification_key<ppT> &&vk) : 
				pp(std::move(pp)),
				pk(std::move(pk)),
				vk(std::move(vk))
		{};

		bool operator==(const r1cs_HFAL_ppzksnark_keypair<ppT> &other) const;
		friend std::ostream &operator<<<ppT>(std::ostream &out, const r1cs_HFAL_ppzksnark_keypair<ppT> &KEYPAIR);
		friend std::istream &operator>><ppT>(std::istream &in, r1cs_HFAL_ppzksnark_keypair<ppT> &KEYPAIR);
	};

	template <typename ppT>
	class r1cs_HFAL_ppzksnark_hash;

	template <typename ppT>
	std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_ppzksnark_hash<ppT> &proof);

	template <typename ppT>
	std::istream &operator>>(std::istream &in, r1cs_HFAL_ppzksnark_hash<ppT> &proof);
	
	template <typename ppT>
	class r1cs_HFAL_ppzksnark_hash{
	  public:
		libff::G1<ppT> HASH;

		r1cs_HFAL_ppzksnark_hash();
		r1cs_HFAL_ppzksnark_hash(libff::G1<ppT> &&HASH) :
			HASH(std::move(HASH))
		{};

		size_t HASH_size() const
		{
			return 1;
		}
		size_t size_in_bits() const
		{
			return HASH_size() * libff::G1<ppT>::size_in_bits();
		}
		void print_size() const
		{
			libff::print_indent(); printf("* XP2 hash size in bits: %zu\n", this->size_in_bits());
		}

		bool operator==(const r1cs_HFAL_ppzksnark_hash<ppT> &other) const;
		friend std::ostream &operator<<<ppT>(std::ostream &out, const r1cs_HFAL_ppzksnark_hash<ppT> &HASH);
		friend std::istream &operator>><ppT>(std::istream &in, r1cs_HFAL_ppzksnark_hash<ppT> &HASH);
	};

	template <typename ppT>
	class r1cs_HFAL_ppzksnark_proof;

	template <typename ppT>
	std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_ppzksnark_proof<ppT> &proof);

	template <typename ppT>
	std::istream &operator>>(std::istream &in, r1cs_HFAL_ppzksnark_proof<ppT> &proof);

	template <typename ppT>
	class r1cs_HFAL_ppzksnark_proof
	{
	  public:
	  	libff::G1<ppT> proof;

		r1cs_HFAL_ppzksnark_proof();
		r1cs_HFAL_ppzksnark_proof(libff::G1<ppT> &&proof) :
			proof(std::move(proof))
		{};

		size_t proof_size() const
		{
			return 1;
		}
		size_t size_in_bits() const
		{
			return proof_size() * libff::G1<ppT>::size_in_bits();
		}
		void print_size() const
		{
			libff::print_indent(); printf("* XP2 Proof size in bits: %zu\n", this->size_in_bits());
		}


		bool operator==(const r1cs_HFAL_ppzksnark_proof<ppT> &other) const;
		friend std::ostream &operator<<<ppT>(std::ostream &out, const r1cs_HFAL_ppzksnark_proof<ppT> &proof);
		friend std::istream &operator>><ppT>(std::istream &in, r1cs_HFAL_ppzksnark_proof<ppT> &proof);
	};

	template <typename ppT>
	r1cs_HFAL_ppzksnark_pp<ppT> r1cs_HFAL_ppzksnark_xp2_setup(const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input);

	template<typename ppT>
	r1cs_HFAL_ppzksnark_hash<ppT> r1cs_HFAL_ppzksnark_xp2_hash(const r1cs_HFAL_ppzksnark_pp<ppT> &pp,
															   const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input);

	template<typename ppT>
	r1cs_HFAL_ppzksnark_keypair<ppT> r1cs_HFAL_ppzksnark_xp2_generator(r1cs_HFAL_ppzksnark_pp<ppT> &pp,
																	   accumulation_vector<libff::G1<ppT> > &gamma_F);
	
	template<typename ppT>
	r1cs_HFAL_ppzksnark_proof<ppT> r1cs_HFAL_ppzksnark_xp2_prover(const r1cs_HFAL_ppzksnark_proving_key<ppT> &pk,
																  const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input,
																  const accumulation_vector<libff::G1<ppT> > &ax);

	template<typename ppT>
	bool r1cs_HFAL_ppzksnark_xp2_verifier(const r1cs_HFAL_ppzksnark_verification_key<ppT> &vk, 
										  const r1cs_HFAL_ppzksnark_hash<ppT> &hash, 
										  const accumulation_vector<libff::G1<ppT> > &ax, 
										  const r1cs_HFAL_ppzksnark_proof<ppT> &proof);

}
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_HFAL_ppzksnark/r1cs_HFAL_ppzksnark.tcc>

#endif


