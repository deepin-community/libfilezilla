#ifndef LIBFILEZILLA_GLUE_DLL_HEADER
#define LIBFILEZILLA_GLUE_DLL_HEADER

#include "../libfilezilla.hpp"

#ifdef FZ_WINDOWS

#include "./windows.hpp"

namespace fz {

/**
 * \brief Encapsulates a DLL
 *
 * The DLL is loaded up on construction and freed on destruction.
 */
class FZ_PUBLIC_SYMBOL dll final
{
public:
	/// Open the specified library with the passed in flags.
	explicit dll(wchar_t const* name, DWORD flags)
	{
		h_ = LoadLibraryExW(name, nullptr, flags);
	}

	/// Closes the library and frees related resources
	~dll() {
		if (h_) {
			FreeLibrary(h_);
		}
	}

	dll(dll const&) = delete;
	dll& operator=(dll const&) = delete;

	explicit operator bool() const {
		return h_ != nullptr;
	}

	/**
	 * \brief Retrieves the address of an exported symbol in the library
	 *
	 * Cast the address to the proper type with reinterpret_cast
	 */
	void *operator[](char const *name) {
		return h_ ? reinterpret_cast<void*>(::GetProcAddress(h_, name)) : nullptr;
	}

private:
	HMODULE h_{};
};

/**
 * \brief A collection of commonly used dlls.
 *
 */
class FZ_PUBLIC_SYMBOL shdlls final
{
protected:
	shdlls();
	~shdlls();

	shdlls(shdlls const&) = delete;
	shdlls* operator=(shdlls const&) = delete;

public:
	static shdlls& get();

	dll shell32_; ///< The Shell32 DLL
	dll ole32_;   ///< The Ole32 DLL
};

}

#else
#error This file is for Windows only
#endif

#endif

