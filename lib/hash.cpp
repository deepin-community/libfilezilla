#include "libfilezilla/libfilezilla.hpp"

#include "libfilezilla/hash.hpp"
#include "libfilezilla/encode.hpp"

#include <nettle/hmac.h>
#include <nettle/md5.h>
#include <nettle/pbkdf2.h>

// Undo Nettle's horrible namespace mangling fuckery
#ifdef pbkdf2_hmac_sha256
#undef pbkdf2_hmac_sha256
#endif

#include <nettle/sha2.h>

#include <string.h>

namespace fz {

class hash_accumulator::impl
{
public:
	virtual ~impl() = default;

	virtual std::vector<uint8_t> export_state() {
		return {};
	}

	virtual bool import_state(std::vector<uint8_t> const&) {
		return false;
	}

	virtual bool selftest() {
		return false;
	}

	virtual void update(uint8_t const* data, size_t size) = 0;
	virtual void reinit() = 0;
	virtual std::vector<uint8_t> digest() = 0;
};

class hash_accumulator_md5 final : public hash_accumulator::impl
{
public:
	hash_accumulator_md5()
	{
		reinit();
	}

	virtual void update(uint8_t const* data, size_t size) override
	{
		nettle_md5_update(&ctx_, size, data);
	}

	virtual void reinit() override
	{
		nettle_md5_init(&ctx_);
	}

	virtual std::vector<uint8_t> digest() override
	{
		std::vector<uint8_t> ret;
		ret.resize(MD5_DIGEST_SIZE);
		nettle_md5_digest(&ctx_, ret.size(), ret.data());
		return ret;
	}

private:
	md5_ctx ctx_;
};

class hash_accumulator_sha1 final : public hash_accumulator::impl
{
public:
	hash_accumulator_sha1()
	{
		reinit();
	}

	virtual void update(uint8_t const* data, size_t size) override
	{
		nettle_sha1_update(&ctx_, size, data);
	}

	virtual void reinit() override
	{
		nettle_sha1_init(&ctx_);
	}

	virtual std::vector<uint8_t> export_state() override
	{
		static_assert(sizeof(ctx_.state[0]) == 4);
		static_assert(sizeof(ctx_.count) == 8);

		std::vector<uint8_t> ret;
		ret.resize(1 + _SHA1_DIGEST_LENGTH * 4 + 8 + ctx_.index);

		// version
		uint8_t* out = ret.data();
		*(out++) = 0;

		// state
		for (size_t i = 0; i < _SHA1_DIGEST_LENGTH; ++i) {
			uint32_t s = ctx_.state[i];
			for (size_t j = 0; j < 4; ++j) {
				*(out++) = s & 0xffu;
				s >>= 8;
			}
		}

		// count
		uint64_t c = ctx_.count;
		for (size_t i = 0; i < 8; ++i) {
			*(out++) = c & 0xffu;
			c >>= 8;
		}

		// index and block
		memcpy(out, ctx_.block, ctx_.index);

		return ret;
	}

	virtual bool import_state(std::vector<uint8_t> const& state) override
	{
		if (state.size() < 1 + _SHA1_DIGEST_LENGTH * 4 + 8) {
			return false;
		}

		if (state.size() > 1 + _SHA1_DIGEST_LENGTH * 4 + 8 + SHA1_BLOCK_SIZE) {
			return false;
		}

		uint8_t const* in = state.data();
		if (*(in++) != 0) {
			return false;
		}

		for (size_t i = 0; i < _SHA1_DIGEST_LENGTH; ++i) {
			ctx_.state[i] = 0;
			for (size_t j = 0; j < 4; ++j) {
				ctx_.state[i] |= static_cast<uint32_t>(*(in++)) << (j * 8);
			}
		}

		ctx_.count = 0;
		for (size_t i = 0; i < 8; ++i) {
			ctx_.count |= static_cast<uint64_t>(*(in++)) << (i * 8);
		}

		ctx_.index = state.size() - (1 + _SHA1_DIGEST_LENGTH * 4 + 8);
		memcpy(ctx_.block, in, ctx_.index);

		return true;
	}

	virtual bool selftest() override
	{
		static bool const result = []{
			auto const first = fz::hex_decode("86dac278131014170074f3549de07ed6cf9fb0daed7ec5ce9d9b68e3e0c67c5407d56e932685e7b0283996f45ccc328ae0c34cd9a5f08d6503bdfe1b4091b41055d8f2140b68d7159f3db271b5106a65a638dec20c10fbcae734ae283e03b498ceeb2dde8f17ab6c36dd75e11e62b14876");
			auto const second = fz::hex_decode("474c1d9ca5c401424e2770765ca3d690f2334ea4eba6f1273e61ba107182e064ed52486a0766e2a56e6d290fad0f5148834a1a21aa08a200f0c25febfd9e8716a9e56ebdce4a93529a63e9b31b92259935e97fb23fd13e5e1f571b4a57ed632c57bd503ca08001238cbe06c12c9b6acb28");
			auto const digest = fz::hex_decode("6b774b870027859cc858092f46f3176fed31d837");
			auto const state = fz::hex_decode("001c1079d268722270cdd59f0c22fa19a357dd64e1010000000000000055d8f2140b68d7159f3db271b5106a65a638dec20c10fbcae734ae283e03b498ceeb2dde8f17ab6c36dd75e11e62b14876");

			hash_accumulator_sha1 h1;
			h1.update(first.data(), first.size());

			if (h1.export_state() != state) {
				return false;
			}

			hash_accumulator_sha1 h2;
			if (!h2.import_state(state)) {
				return false;
			}
			h1.update(second.data(), second.size());
			h2.update(second.data(), second.size());

			if (h1.digest() != digest) {
				return false;
			}
			if (h2.digest() != digest) {
				return false;
			}

			return true;
		}();
		return result;
	}

	virtual std::vector<uint8_t> digest() override
	{
		std::vector<uint8_t> ret;
		ret.resize(SHA1_DIGEST_SIZE);
		nettle_sha1_digest(&ctx_, ret.size(), ret.data());
		return ret;
	}

private:
	sha1_ctx ctx_;
};

class hash_accumulator_sha256 final : public hash_accumulator::impl
{
public:
	hash_accumulator_sha256()
	{
		reinit();
	}

	virtual void update(uint8_t const* data, size_t size) override
	{
		nettle_sha256_update(&ctx_, size, data);
	}

	virtual void reinit() override
	{
		nettle_sha256_init(&ctx_);
	}

	virtual std::vector<uint8_t> digest() override
	{
		std::vector<uint8_t> ret;
		ret.resize(SHA256_DIGEST_SIZE);
		nettle_sha256_digest(&ctx_, ret.size(), ret.data());
		return ret;
	}

private:
	sha256_ctx ctx_;
};

class hash_accumulator_sha512 final : public hash_accumulator::impl
{
public:
	hash_accumulator_sha512()
	{
		reinit();
	}

	virtual void update(uint8_t const* data, size_t size) override
	{
		nettle_sha512_update(&ctx_, size, data);
	}

	virtual void reinit() override
	{
		nettle_sha512_init(&ctx_);
	}

	virtual std::vector<uint8_t> digest() override
	{
		std::vector<uint8_t> ret;
		ret.resize(SHA512_DIGEST_SIZE);
		nettle_sha512_digest(&ctx_, ret.size(), ret.data());
		return ret;
	}

private:
	sha512_ctx ctx_;
};

hash_accumulator::hash_accumulator(hash_algorithm algorithm)
{
	switch (algorithm) {
	case hash_algorithm::md5:
		impl_ = new hash_accumulator_md5;
		break;
	case hash_algorithm::sha1:
		impl_ = new hash_accumulator_sha1;
		break;
	case hash_algorithm::sha256:
		impl_ = new hash_accumulator_sha256;
		break;
	case hash_algorithm::sha512:
		impl_ = new hash_accumulator_sha512;
		break;
	}
}

hash_accumulator::~hash_accumulator()
{
	delete impl_;
}

void hash_accumulator::reinit()
{
	impl_->reinit();
}

void hash_accumulator::update(std::string_view const& data)
{
	if (!data.empty()) {
		impl_->update(reinterpret_cast<uint8_t const*>(data.data()), data.size());
	}
}

void hash_accumulator::update(std::basic_string_view<uint8_t> const& data)
{
	if (!data.empty()) {
		impl_->update(data.data(), data.size());
	}
}

void hash_accumulator::update(std::vector<uint8_t> const& data)
{
	if (!data.empty()) {
		impl_->update(data.data(), data.size());
	}
}

void hash_accumulator::update(uint8_t const* data, size_t size)
{
	impl_->update(data, size);
}

std::vector<uint8_t> hash_accumulator::digest()
{
	return impl_->digest();
}

std::vector<std::uint8_t> hash_accumulator::export_state()
{
	if (!impl_ || !impl_->selftest()) {
		return {};
	}
	return impl_->export_state();
}

bool hash_accumulator::import_state(std::vector<std::uint8_t> const& state)
{
	reinit();
	if (!impl_ || !impl_->selftest()) {
		return false;
	}
	bool ret = impl_->import_state(state);
	if (!ret) {
		reinit();
	}
	return ret;
}

namespace {
// In C++17, require ContiguousContainer
template<typename DataContainer>
std::vector<uint8_t> md5_impl(DataContainer const& in)
{
	static_assert(sizeof(typename DataContainer::value_type) == 1, "Bad container type");

	hash_accumulator_md5 acc;
	if (!in.empty()) {
		acc.update(reinterpret_cast<uint8_t const*>(in.data()), in.size());
	}
	return acc.digest();
}

template<typename DataContainer>
std::vector<uint8_t> sha1_impl(DataContainer const& in)
{
	static_assert(sizeof(typename DataContainer::value_type) == 1, "Bad container type");

	hash_accumulator_sha1 acc;
	if (!in.empty()) {
		acc.update(reinterpret_cast<uint8_t const*>(in.data()), in.size());
	}
	return acc.digest();
}

template<typename DataContainer>
std::vector<uint8_t> sha256_impl(DataContainer const& in)
{
	static_assert(sizeof(typename DataContainer::value_type) == 1, "Bad container type");

	hash_accumulator_sha256 acc;
	if (!in.empty()) {
		acc.update(reinterpret_cast<uint8_t const*>(in.data()), in.size());
	}
	return acc.digest();
}

template<typename DataContainer>
std::vector<uint8_t> sha512_impl(DataContainer const& in)
{
	static_assert(sizeof(typename DataContainer::value_type) == 1, "Bad container type");

	hash_accumulator_sha512 acc;
	if (!in.empty()) {
		acc.update(reinterpret_cast<uint8_t const*>(in.data()), in.size());
	}
	return acc.digest();
}

template<typename KeyContainer, typename DataContainer>
std::vector<uint8_t> hmac_sha1_impl(KeyContainer const& key, DataContainer const& data)
{
	static_assert(sizeof(typename KeyContainer::value_type) == 1, "Bad container type");
	static_assert(sizeof(typename DataContainer::value_type) == 1, "Bad container type");

	std::vector<uint8_t> ret;

	hmac_sha1_ctx ctx;
	nettle_hmac_sha1_set_key(&ctx, key.size(), key.empty() ? nullptr : reinterpret_cast<uint8_t const*>(key.data()));

	if (!data.empty()) {
		nettle_hmac_sha1_update(&ctx, data.size(), reinterpret_cast<uint8_t const*>(data.data()));
	}

	ret.resize(SHA1_DIGEST_SIZE);
	nettle_hmac_sha1_digest(&ctx, ret.size(), ret.data());

	return ret;
}

template<typename KeyContainer, typename DataContainer>
std::vector<uint8_t> hmac_sha256_impl(KeyContainer const& key, DataContainer const& data)
{
	static_assert(sizeof(typename KeyContainer::value_type) == 1, "Bad container type");
	static_assert(sizeof(typename DataContainer::value_type) == 1, "Bad container type");

	std::vector<uint8_t> ret;

	hmac_sha256_ctx ctx;
	nettle_hmac_sha256_set_key(&ctx, key.size(), key.empty() ? nullptr : reinterpret_cast<uint8_t const*>(key.data()));

	if (!data.empty()) {
		nettle_hmac_sha256_update(&ctx, data.size(), reinterpret_cast<uint8_t const*>(data.data()));
	}

	ret.resize(SHA256_DIGEST_SIZE);
	nettle_hmac_sha256_digest(&ctx, ret.size(), ret.data());

	return ret;
}
}

std::vector<uint8_t> md5(std::vector<uint8_t> const& data)
{
	return md5_impl(data);
}

std::vector<uint8_t> md5(std::string_view const& data)
{
	return md5_impl(data);
}

std::vector<uint8_t> sha1(std::vector<uint8_t> const& data)
{
	return sha1_impl(data);
}

std::vector<uint8_t> sha1(std::string_view const& data)
{
	return sha1_impl(data);
}

std::vector<uint8_t> sha256(std::vector<uint8_t> const& data)
{
	return sha256_impl(data);
}

std::vector<uint8_t> sha256(std::string_view const& data)
{
	return sha256_impl(data);
}

std::vector<uint8_t> sha512(std::vector<uint8_t> const& data)
{
	return sha512_impl(data);
}

std::vector<uint8_t> sha512(std::string_view const& data)
{
	return sha512_impl(data);
}

std::vector<uint8_t> hmac_sha1(std::string_view const& key, std::string_view const& data)
{
	return hmac_sha1_impl(key, data);
}

std::vector<uint8_t> hmac_sha1(std::vector<uint8_t> const& key, std::vector<uint8_t> const& data)
{
	return hmac_sha1_impl(key, data);
}

std::vector<uint8_t> hmac_sha1(std::vector<uint8_t> const& key, std::string_view const& data)
{
	return hmac_sha1_impl(key, data);
}

std::vector<uint8_t> hmac_sha1(std::string_view const& key, std::vector<uint8_t> const& data)
{
	return hmac_sha1_impl(key, data);
}

std::vector<uint8_t> hmac_sha256(std::string_view const& key, std::string_view const& data)
{
	return hmac_sha256_impl(key, data);
}

std::vector<uint8_t> hmac_sha256(std::vector<uint8_t> const& key, std::vector<uint8_t> const& data)
{
	return hmac_sha256_impl(key, data);
}

std::vector<uint8_t> hmac_sha256(std::vector<uint8_t> const& key, std::string_view const& data)
{
	return hmac_sha256_impl(key, data);
}

std::vector<uint8_t> hmac_sha256(std::string_view const& key, std::vector<uint8_t> const& data)
{
	return hmac_sha256_impl(key, data);
}

std::vector<uint8_t> pbkdf2_hmac_sha256(std::basic_string_view<uint8_t> const& password, std::basic_string_view<uint8_t> const& salt, size_t length, unsigned int iterations)
{
	std::vector<uint8_t> ret;

	if (!password.empty() && !salt.empty()) {
		ret.resize(length);
		nettle_pbkdf2_hmac_sha256(password.size(), password.data(), iterations, salt.size(), salt.data(), length, ret.data());
	}

	return ret;
}
}
