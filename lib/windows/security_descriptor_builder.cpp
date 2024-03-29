#include "security_descriptor_builder.hpp"

#ifdef FZ_WINDOWS

#include <array>
#include <map>

#include <sddl.h>

namespace fz {

namespace {
template<typename T>
struct holder final
{
	holder() = default;
	~holder()
	{
		clear();
	}

	static holder create(size_t s) {
		holder h;
		h.v_ = reinterpret_cast<T*>(new uint8_t[s]);
		h.size_ = s;
		h.delete_ = true;
		return h;
	}

	void clear()
	{
		if (delete_) {
			delete[] reinterpret_cast<uint8_t*>(v_);
		}
		size_ = 0;
		v_ = nullptr;
	}

	static holder create(void* v, bool del)
	{
		holder h;
		h.v_ = reinterpret_cast<T*>(v);
		h.size_ = v ? size_t(-1) : 0;
		h.delete_ = del;
		return h;
	}

	holder(holder&& h) noexcept
		: v_(h.v_)
		, size_(h.size_)
	{
		h.v_ = nullptr;
		h.size_ = 0;
		delete_ = h.delete_;
	}

	holder& operator=(holder&& h) noexcept {
		if (this != &h) {
			clear();
			v_ = h.v_;
			size_ = h.size_;
			h.v_ = nullptr;
			h.size_ = 0;
			delete_ = h.delete_;
		}
		return *this;
	}

	size_t size() const { return size_; }

	explicit operator bool() const { return v_ != nullptr; }

	holder(holder const&) = delete;
	holder& operator=(holder const&) = delete;

	T* get() { return v_; }
	T& operator*() { return *v_; }
	T* operator->() { return v_; }

private:
	bool delete_{};
	T* v_{};
	size_t size_{};
};
}

struct security_descriptor_builder::impl
{
	holder<SID> get_sid(entity e);
	bool init_user();

	std::map<entity, DWORD> rights_;

	holder<TOKEN_USER> user_;
	holder<ACL> acl_;
	SECURITY_DESCRIPTOR sd_{};
};

security_descriptor_builder::security_descriptor_builder()
	: impl_(std::make_unique<impl>())
{
}

security_descriptor_builder::~security_descriptor_builder()
{
}

void security_descriptor_builder::add(entity e, DWORD rights)
{
	impl_->acl_.clear();
	impl_->rights_[e] = rights;
}

ACL* security_descriptor_builder::get_acl(sdb_flags f)
{
	if (impl_->acl_) {
		return impl_->acl_.get();
	}

	if (!impl_->init_user()) {
		return nullptr;
	}

	DWORD const needed = static_cast<DWORD>(sizeof(ACL) + (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + SECURITY_MAX_SID_SIZE) * impl_->rights_.size());
	auto acl = holder<ACL>::create(needed);

	if (InitializeAcl(acl.get(), needed, ACL_REVISION)) {
		for (auto it = impl_->rights_.cbegin(); acl && it != impl_->rights_.cend(); ++it) {
			auto sid = impl_->get_sid(it->first);
			DWORD flags = (f & sdb_flags::inheritable) ? (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE) : 0;
			if (!sid || !AddAccessAllowedAceEx(acl.get(), ACL_REVISION, flags, it->second, sid.get())) {
				return {};
			}
		}
		impl_->acl_ = std::move(acl);
	}

	if (impl_->acl_) {
		InitializeSecurityDescriptor(&impl_->sd_, SECURITY_DESCRIPTOR_REVISION);
		SetSecurityDescriptorControl(&impl_->sd_, SE_DACL_PROTECTED, (f & sdb_flags::inherit_from_parent) ? 0 : SE_DACL_PROTECTED);
		SetSecurityDescriptorDacl(&impl_->sd_, TRUE, impl_->acl_.get(), FALSE);
		SetSecurityDescriptorOwner(&impl_->sd_, impl_->user_->User.Sid, FALSE);
		SetSecurityDescriptorGroup(&impl_->sd_, NULL, FALSE);
		SetSecurityDescriptorSacl(&impl_->sd_, FALSE, NULL, FALSE);
	}

	return impl_->acl_.get();
}

SECURITY_DESCRIPTOR* security_descriptor_builder::get_sd(sdb_flags f)
{
	if (!get_acl(f)) {
		return nullptr;
	}

	return &impl_->sd_;
}

holder<SID> security_descriptor_builder::impl::get_sid(entity e)
{
	if (e == self) {
		init_user();
		return holder<SID>::create(user_ ? user_->User.Sid : nullptr, false);
	}
	else {
		auto sid = holder<SID>::create(SECURITY_MAX_SID_SIZE);
		DWORD l = SECURITY_MAX_SID_SIZE;
		if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, sid.get(), &l)) {
			return {};
		}
		return sid;
	}
}

namespace {
holder<TOKEN_USER> GetUserFromToken(HANDLE token)
{
	DWORD needed{};
	GetTokenInformation(token, TokenUser, NULL, 0, &needed);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		auto user = holder<TOKEN_USER>::create(needed);
		if (GetTokenInformation(token, TokenUser, user.get(), needed, &needed)) {
			return user;
		}
	}

	return {};
}
}

bool security_descriptor_builder::impl::init_user()
{
	if (user_) {
		return true;
	}

	HANDLE token{INVALID_HANDLE_VALUE};
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		return false;
	}
	user_ = GetUserFromToken(token);

	CloseHandle(token);

	return user_.operator bool();
}

std::string GetSidFromToken(HANDLE h)
{
	auto user = GetUserFromToken(h);
	if (user) {
		LPSTR sid{};
		if (ConvertSidToStringSidA(user->User.Sid, &sid) != 0) {
			std::string ret = sid;
			LocalFree(sid);
			return ret;
		}
	}
	return {};
}

namespace {
holder<TOKEN_PRIVILEGES> GetPrivileges(HANDLE token)
{
	DWORD needed{};
	GetTokenInformation(token, TokenPrivileges, NULL, 0, &needed);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		auto privs = holder<TOKEN_PRIVILEGES>::create(needed);
		if (GetTokenInformation(token, TokenPrivileges, privs.get(), needed, &needed)) {
			return privs;
		}
	}

	return {};
}
}

bool DropAdminPrivilegesFromToken(HANDLE h)
{
	auto privs = GetPrivileges(h);
	if (!privs) {
		return false;
	}

	std::array<LUID, 2> allowed;
	if (!LookupPrivilegeValue(nullptr, SE_INC_WORKING_SET_NAME, &allowed[0])) {
		return false;
	}
	if (!LookupPrivilegeValue(nullptr, SE_CHANGE_NOTIFY_NAME, &allowed[1])) {
		return false;
	}

	DWORD out{};
	for (DWORD i = 0; i < privs->PrivilegeCount; ++i) {
		bool found{};
		for (auto const& luid : allowed) {
			if (std::tie(luid.LowPart, luid.HighPart) == std::tie(privs->Privileges[i].Luid.LowPart, privs->Privileges[i].Luid.HighPart)) {
				found = true;
				break;
			}
		}
		if (!found) {
			privs->Privileges[out].Luid = privs->Privileges[i].Luid;
			privs->Privileges[out].Attributes = SE_PRIVILEGE_REMOVED;
			++out;
		}
	}
	if (out) {
		privs->PrivilegeCount = out;
		if (!AdjustTokenPrivileges(h, false, privs.get(), privs.size(), nullptr, nullptr)) {
			return false;
		}
	}

	return true;
}

}
#endif
