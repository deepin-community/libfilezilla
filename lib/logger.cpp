#include "libfilezilla/logger.hpp"

namespace fz {

null_logger& get_null_logger()
{
	static null_logger log;
	return log;
}

}

