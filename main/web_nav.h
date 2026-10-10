#pragma once

#include <stddef.h>

/* The menu of the page header for the request path `uri`: the four groups, and under them
 * the pages of the group that holds it. Returns that group's name for the phone bar, "" off
 * the menu. The texts are in the language of this request (T()), so call it on the httpd
 * task only. */
const char *web_nav_build(char *out, size_t cap, const char *uri, const char *lc);
