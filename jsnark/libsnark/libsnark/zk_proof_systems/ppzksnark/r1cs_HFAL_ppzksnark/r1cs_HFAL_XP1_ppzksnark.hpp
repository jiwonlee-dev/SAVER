#ifndef R1CS_HFAL_XP1_PPZKSNARK_HPP_
#define R1CS_HFAL_XP1_PPZKSNARK_HPP_

#include <memory>

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/common/data_structures/accumulation_vector.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_HFAL_ppzksnark/r1cs_gg_ppzksnark_params.hpp>

namespace libsnark{

	template <typename ppT>
	class r1cs_HFAL_XP1_ppzksnark_pp;

	template <typename ppT>
	std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_XP1_ppzksnark_pp<ppT> &pp);

	template <typename ppT>
	std::istream &operator>>(std::istream &in, r1cs_HFAL_XP1_ppzksnark_pp<ppT> &pp);
	
	template<typename ppT>
	class r1cs_HFAL_XP1_ppzksnark_pp{
	public:
    	libff::G1_vector<ppT> hfal_H;

		r1cs_HFAL_XP1_ppzksnark_pp() {};
    	r1cs_HFAL_XP1_ppzksnark_pp<ppT>& operator=(const r1cs_HFAL_XP1_ppzksnark_pp<ppT> &other) = default;
		r1cs_HFAL_XP1_ppzksnark_pp(	const libff::G1_vector<ppT> &hfal_H) :
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
			libff::print_indent(); printf("* XP1 PP size in bits: %zu\n",this->size_in_bits());
		}
		bool operator==(const r1cs_HFAL_XP1_ppzksnark_pp<ppT> &other) const;
		friend std::ostream &operator<<<ppT>(std::ostream &out, const r1cs_HFAL_XP1_ppzksnark_pp<ppT> &pp);
		friend std::istream &operator>><ppT>(std::istream &in, r1cs_HFAL_XP1_ppzksnark_pp<ppT> &pp);
	};

	template <typename ppT>
	class r1cs_HFAL_XP1_ppzksnark_proving_key;

	template <typename ppT>
	std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_XP1_ppzksnark_proving_key<ppT> &pk);

	template <typename ppT>
	std::istream &operator>>(std::istream &in, r1cs_HFAL_XP1_ppzksnark_proving_key<ppT> &pk);

	template <typename ppT>
	class r1cs_HFAL_XP1_ppzksnark_proving_key{
	public:
    	accumulation_vector<libff::G1<ppT> > F_g1;
		libff::G1_vector<ppT> T_g1;
		libff::G1_vector<ppT> R_g1;

		r1cs_HFAL_XP1_ppzksnark_proving_key(){};
		r1cs_HFAL_XP1_ppzksnark_proving_key<ppT> &operator=(const r1cs_HFAL_XP1_ppzksnark_proving_key<ppT> &other) = default;
		r1cs_HFAL_XP1_ppzksnark_proving_key(const r1cs_HFAL_XP1_ppzksnark_proving_key<ppT> &other) = default;
		r1cs_HFAL_XP1_ppzksnark_proving_key(r1cs_HFAL_XP1_ppzksnark_proving_key<ppT> &&other) = default;
		r1cs_HFAL_XP1_ppzksnark_proving_key(const accumulation_vector<libff::G1<ppT>> &F_g1,
											const libff::G1_vector<ppT> &T_g1,
											const libff::G1_vector<ppT> &R_g1) : 
										F_g1(F_g1),
										T_g1(T_g1),
										R_g1(R_g1)
										{};

		size_t F_g1_size_in_bits() const
		{
			return F_g1.size()*libff::G1<ppT>::size_in_bits();
		}
		size_t T_g1_size_in_bits() const
		{
			return T_g1.size()*libff::G1<ppT>::size_in_bits();
		}
		size_t R_g1_size_in_bits() const
		{
			return R_g1.size()*libff::G1<ppT>::size_in_bits();
		}
		size_t size_in_bits() const
		{
			return F_g1.size_in_bits() + libff::size_in_bits(T_g1) + libff::size_in_bits(R_g1);
		}
		void print_size() const
		{
			libff::print_indent(); printf("* XP1 PK size in bits: %zu\n",this->size_in_bits());
		}

    	bool operator==(const r1cs_HFAL_XP1_ppzksnark_proving_key<ppT> &other) const;
    	friend std::ostream& operator<< <ppT>(std::ostream &out, const r1cs_HFAL_XP1_ppzksnark_proving_key<ppT> &pk);
    	friend std::istream& operator>> <ppT>(std::istream &in, r1cs_HFAL_XP1_ppzksnark_proving_key<ppT> &pk);
	};

	template <typename ppT>
	class r1cs_HFAL_XP1_ppzksnark_verification_key;

	template <typename ppT>
	std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_XP1_ppzksnark_verification_key<ppT> &vk);

	template <typename ppT>
	std::istream &operator>>(std::istream &in, r1cs_HFAL_XP1_ppzksnark_verification_key<ppT> &vk);

	template <typename ppT>
	class r1cs_HFAL_XP1_ppzksnark_verification_key{
	public:
		libff::G2<ppT> u_g2;
		libff::G2<ppT> v_g2;
		libff::G2<ppT> w_g2;

		r1cs_HFAL_XP1_ppzksnark_verification_key() = default;
		r1cs_HFAL_XP1_ppzksnark_verification_key(const libff::G2<ppT> &&u_g2,
												 const libff::G2<ppT> &&v_g2,
												 const libff::G2<ppT> &&w_g2) :
			u_g2(std::move(u_g2)),
			v_g2(std::move(v_g2)),
			w_g2(std::move(w_g2))
		{};

		size_t u_g2_size() const
		{
			return 2;
		}
		size_t v_g2_size() const
		{
			return 2;
		}
		size_t w_g2_size() const
		{
			return 2;
		}
		size_t size_in_bits() const
		{
			return u_g2_size() * libff::G2<ppT>::size_in_bits() 
				+ v_g2_size() * libff::G2<ppT>::size_in_bits() 
				+ w_g2_size() * libff::G2<ppT>::size_in_bits();
		}
		void print_size() const
		{
			libff::print_indent(); printf("* XP1 VK size in bits: %zu\n",this->size_in_bits());
		}
    	bool operator==(const r1cs_HFAL_XP1_ppzksnark_verification_key<ppT> &other) const;
    	friend std::ostream& operator<< <ppT>(std::ostream &out, const r1cs_HFAL_XP1_ppzksnark_verification_key<ppT> &pk);
    	friend std::istream& operator>> <ppT>(std::istream &in, r1cs_HFAL_XP1_ppzksnark_verification_key<ppT> &pk);
	};

	template <typename ppT>
	class r1cs_HFAL_XP1_ppzksnark_keypair;

	template <typename ppT>
	std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_XP1_ppzksnark_keypair<ppT> &KEYPAIR);

	template <typename ppT>
	std::istream &operator>>(std::istream &in, r1cs_HFAL_XP1_ppzksnark_keypair<ppT> &KEYPAIR);
	
	template <typename ppT>
	class r1cs_HFAL_XP1_ppzksnark_keypair
	{
	  public:
	  	r1cs_HFAL_XP1_ppzksnark_pp<ppT> pp;
		r1cs_HFAL_XP1_ppzksnark_proving_key<ppT> pk;
		r1cs_HFAL_XP1_ppzksnark_verification_key<ppT> vk;

		r1cs_HFAL_XP1_ppzksnark_keypair(const r1cs_HFAL_XP1_ppzksnark_keypair<ppT> &other):
			pp(std::move(other.pp)),
			pk(std::move(other.pk)),
			vk(std::move(other.vk))
		{};
		r1cs_HFAL_XP1_ppzksnark_keypair(r1cs_HFAL_XP1_ppzksnark_pp<ppT> &&pp,
									r1cs_HFAL_XP1_ppzksnark_proving_key<ppT> &&pk,
									r1cs_HFAL_XP1_ppzksnark_verification_key<ppT> &&vk) : 
				pp(std::move(pp)),
				pk(std::move(pk)),
				vk(std::move(vk))
		{};

		bool operator==(const r1cs_HFAL_XP1_ppzksnark_keypair<ppT> &other) const;
		friend std::ostream &operator<<<ppT>(std::ostream &out, const r1cs_HFAL_XP1_ppzksnark_keypair<ppT> &KEYPAIR);
		friend std::istream &operator>><ppT>(std::istream &in, r1cs_HFAL_XP1_ppzksnark_keypair<ppT> &KEYPAIR);
	};

	template <typename ppT>
	class r1cs_HFAL_XP1_ppzksnark_hash;

	template <typename ppT>
	std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_XP1_ppzksnark_hash<ppT> &proof);

	template <typename ppT>
	std::istream &operator>>(std::istream &in, r1cs_HFAL_XP1_ppzksnark_hash<ppT> &proof);
	
	template <typename ppT>
	class r1cs_HFAL_XP1_ppzksnark_hash{
	  public:
		libff::G1<ppT> HASH;

		r1cs_HFAL_XP1_ppzksnark_hash();
		r1cs_HFAL_XP1_ppzksnark_hash(libff::G1<ppT> &&HASH) :
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
			libff::print_indent(); printf("* XP1 hash size in bits: %zu\n", this->size_in_bits());
		}

		bool operator==(const r1cs_HFAL_XP1_ppzksnark_hash<ppT> &other) const;
		friend std::ostream &operator<<<ppT>(std::ostream &out, const r1cs_HFAL_XP1_ppzksnark_hash<ppT> &HASH);
		friend std::istream &operator>><ppT>(std::istream &in, r1cs_HFAL_XP1_ppzksnark_hash<ppT> &HASH);
	};

	template <typename ppT>
	class r1cs_HFAL_XP1_ppzksnark_proof;

	template <typename ppT>
	std::ostream &operator<<(std::ostream &out, const r1cs_HFAL_XP1_ppzksnark_proof<ppT> &proof);

	template <typename ppT>
	std::istream &operator>>(std::istream &in, r1cs_HFAL_XP1_ppzksnark_proof<ppT> &proof);

	template <typename ppT>
	class r1cs_HFAL_XP1_ppzksnark_proof
	{
	  public:
	  	libff::G1<ppT> T_sum_G1;
	  	libff::G1<ppT> R_sum_G1;

		r1cs_HFAL_XP1_ppzksnark_proof();
		r1cs_HFAL_XP1_ppzksnark_proof(libff::G1<ppT> &&T_sum_G1,
									  libff::G1<ppT> &&R_sum_G1) :
			T_sum_G1(std::move(T_sum_G1)),
			R_sum_G1(std::move(R_sum_G1))
		{};

		size_t T_sum_G1_size() const
		{
			return 1;
		}
		size_t R_sum_G1_size() const
		{
			return 1;
		}
		size_t size_in_bits() const
		{
			return T_sum_G1_size() * libff::G1<ppT>::size_in_bits()
					+ R_sum_G1_size() * libff::G1<ppT>::size_in_bits();
		}
		void print_size() const
		{
			libff::print_indent(); printf("* XP1 Proof size in bits: %zu\n", this->size_in_bits());
		}


		bool operator==(const r1cs_HFAL_XP1_ppzksnark_proof<ppT> &other) const;
		friend std::ostream &operator<<<ppT>(std::ostream &out, const r1cs_HFAL_XP1_ppzksnark_proof<ppT> &proof);
		friend std::istream &operator>><ppT>(std::istream &in, r1cs_HFAL_XP1_ppzksnark_proof<ppT> &proof);
	};

	template <typename ppT>
	r1cs_HFAL_XP1_ppzksnark_pp<ppT> r1cs_HFAL_XP1_ppzksnark_setup(const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input);

	template<typename ppT>
	r1cs_HFAL_XP1_ppzksnark_hash<ppT> r1cs_HFAL_XP1_ppzksnark_hashing(const r1cs_HFAL_XP1_ppzksnark_pp<ppT> &pp,
															   const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input);

	template<typename ppT>
	r1cs_HFAL_XP1_ppzksnark_keypair<ppT> r1cs_HFAL_XP1_ppzksnark_generator(r1cs_HFAL_XP1_ppzksnark_pp<ppT> &pp,
																	   accumulation_vector<libff::G1<ppT> > &gamma_F);
	
	template<typename ppT>
	r1cs_HFAL_XP1_ppzksnark_proof<ppT> r1cs_HFAL_XP1_ppzksnark_prover(const r1cs_HFAL_XP1_ppzksnark_proving_key<ppT> &pk,
																  const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input,
																  const accumulation_vector<libff::G1<ppT> > &ax);

	template<typename ppT>
	bool r1cs_HFAL_XP1_ppzksnark_verifier(const r1cs_HFAL_XP1_ppzksnark_verification_key<ppT> &vk, 
										  const r1cs_HFAL_XP1_ppzksnark_hash<ppT> &hash, 
										  const accumulation_vector<libff::G1<ppT> > &ax, 
										  const r1cs_HFAL_XP1_ppzksnark_proof<ppT> &proof);

}
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_HFAL_ppzksnark/r1cs_HFAL_XP1_ppzksnark.tcc>

#endif


