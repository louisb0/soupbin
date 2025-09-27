#pragma once

namespace soupbin {

#ifndef SOUPBIN_MAX_CLIENTS
#define SOUPBIN_MAX_CLIENTS 1024
#endif

#ifndef SOUPBIN_BATCH_SIZE
#define SOUPBIN_BATCH_SIZE 16
#endif

int make_server();

} // namespace soupbin
