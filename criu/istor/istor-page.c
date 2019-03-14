#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <uuid/uuid.h>

#include "cr_options.h"
#include "image.h"
#include "util.h"
#include "log.h"

#include "istor/istor-net.h"
#include "istor/istor-page.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif

#define LOG_PREFIX "istor-page: "
