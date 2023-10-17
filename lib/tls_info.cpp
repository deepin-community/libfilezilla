#include "libfilezilla/tls_info.hpp"
#include "tls_layer_impl.hpp"

namespace fz {
x509_certificate::x509_certificate(
		std::vector<uint8_t> const& rawData,
		datetime const& activation_time, datetime const& expiration_time,
		std::string const& serial,
		std::string const& pkalgoname, unsigned int bits,
		std::string const& signalgoname,
		std::string const& fingerprint_sha256,
		std::string const& fingerprint_sha1,
		std::string const& issuer,
		std::string const& subject,
		std::vector<subject_name> const& alt_subject_names,
		bool const self_signed)
	: activation_time_(activation_time)
	, expiration_time_(expiration_time)
	, raw_cert_(rawData)
	, serial_(serial)
	, pkalgoname_(pkalgoname)
	, pkalgobits_(bits)
	, signalgoname_(signalgoname)
	, fingerprint_sha256_(fingerprint_sha256)
	, fingerprint_sha1_(fingerprint_sha1)
	, issuer_(issuer)
	, subject_(subject)
	, alt_subject_names_(alt_subject_names)
	, self_signed_(self_signed)
{
}

x509_certificate::x509_certificate(
	std::vector<uint8_t> && rawData,
	datetime const& activation_time, datetime const& expiration_time,
	std::string const& serial,
	std::string const& pkalgoname, unsigned int bits,
	std::string const& signalgoname,
	std::string const& fingerprint_sha256,
	std::string const& fingerprint_sha1,
	std::string const& issuer,
	std::string const& subject,
	std::vector<subject_name> && alt_subject_names,
	bool const self_signed)
	: activation_time_(activation_time)
	, expiration_time_(expiration_time)
	, raw_cert_(rawData)
	, serial_(serial)
	, pkalgoname_(pkalgoname)
	, pkalgobits_(bits)
	, signalgoname_(signalgoname)
	, fingerprint_sha256_(fingerprint_sha256)
	, fingerprint_sha1_(fingerprint_sha1)
	, issuer_(issuer)
	, subject_(subject)
	, alt_subject_names_(alt_subject_names)
	, self_signed_(self_signed)
{
}

tls_session_info::tls_session_info(std::string const& host, unsigned int port,
		std::string const& protocol,
		std::string const& key_exchange,
		std::string const& session_cipher,
		std::string const& session_mac,
		int algorithm_warnings,
		std::vector<x509_certificate> && peer_certificates,
		std::vector<x509_certificate> && system_trust_chain,
		bool hostname_mismatch)
	: host_(host)
	, port_(port)
	, protocol_(protocol)
	, key_exchange_(key_exchange)
	, session_cipher_(session_cipher)
	, session_mac_(session_mac)
	, algorithm_warnings_(algorithm_warnings)
	, peer_certificates_(peer_certificates)
	, system_trust_chain_(system_trust_chain)
	, hostname_mismatch_(hostname_mismatch)
{
}

std::vector<x509_certificate> load_certificates_file(native_string const& certsfile, bool pem, bool sort, logger_interface * logger)
{
	std::string certdata = read_certificates_file(certsfile, logger);
	if (certdata.empty()) {
		return {};
	}

	return load_certificates(certdata, pem, sort, logger);
}

std::vector<x509_certificate> load_certificates(std::string_view const& certdata, bool pem, bool sort, logger_interface * logger)
{
	cert_list_holder certs;
	if (tls_layer_impl::load_certificates(certdata, pem, certs.certs, certs.certs_size, sort) != GNUTLS_E_SUCCESS) {
		return {};
	}

	std::vector<x509_certificate> certificates;
	certificates.reserve(certs.certs_size);
	for (unsigned int i = 0; i < certs.certs_size; ++i) {
		x509_certificate cert;
		if (tls_layer_impl::extract_cert(certs.certs[i], cert, i + 1 == certs.certs_size, logger)) {
			certificates.emplace_back(std::move(cert));
		}
		else {
			certificates.clear();
			break;
		}
	}

	return certificates;
}

native_string check_certificate_status(std::string_view const& key, std::string_view const& certs, native_string const& password, bool pem)
{
	struct log_to_string: logger_interface
	{
		log_to_string(native_string &str)
			: str_(str)
		{
			level_ = logmsg::error;
		}

		void do_log(logmsg::type, std::wstring && msg) override
		{
			if (!str_.empty())
				str_.append(fzT("\n"));

			str_.append(to_native(msg));
		}

	private:
		native_string &str_;
	};

	native_string ret;
	log_to_string logger(ret);

	gnutls_certificate_credentials_t creds;
	int res = gnutls_certificate_allocate_credentials(&creds);
	if (res < 0) {
		tls_layer_impl::log_gnutls_error(logger, res);
		return ret;
	}

	gnutls_datum_t c;
	c.data = const_cast<unsigned char*>(reinterpret_cast<unsigned char const*>(certs.data()));
	c.size = unsigned(certs.size());

	gnutls_datum_t k;
	k.data = const_cast<unsigned char*>(reinterpret_cast<unsigned char const*>(key.data()));
	k.size = unsigned(key.size());

	res = gnutls_certificate_set_x509_key_mem2(creds, &c,
		&k, pem ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER, password.empty() ? nullptr : to_utf8(password).c_str(), 0);

	gnutls_certificate_free_credentials(creds);

	if (res < 0) {
		tls_layer_impl::log_gnutls_error(logger, res);
		return ret;
	}

	auto x059 = load_certificates(certs, pem, true, &logger);
	if (x059.empty()) {
		return ret;
	}

	auto now = datetime::now();

	if (now < x059[0].get_activation_time()) {
		tls_layer_impl::log_gnutls_error(logger, GNUTLS_E_NOT_YET_ACTIVATED);
		return ret;
	}

	if (x059[0].get_expiration_time() < now) {
		tls_layer_impl::log_gnutls_error(logger, GNUTLS_E_EXPIRED);
		return ret;
	}

	return {};
}

}
