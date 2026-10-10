#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "web_strings.h"

/* Durations, dates, sizes and the device time zone, one spelling for every page. No config.h
 * and no httpd here, so every host suite links this file with web_strings.c alone. */

/* Each output is complete or empty: a cut would leave half a no-break space behind. */

/* TWO: two units ("12 min 22 s"). ONE: one unit, the largest that counts 2 or more ("vor 3 min",
 * "90 s"). PHASE: seconds below 3 min, then two units ("7 min 0 s"). EXACT: whole hours from 2 h,
 * else whole minutes from 2 min, else seconds ("10 min", "60 min"). */
typedef enum { FMT_DUR_TWO, FMT_DUR_ONE, FMT_DUR_PHASE, FMT_DUR_EXACT } fmt_dur_t;
#define FMT_DUR_MAX 16 /* 49709 d 23 h with three no-break spaces: 15 bytes */
#define FMT_AGE_MAX 32 /* vor + no-break space + 15, or 15 + no-break space + ago: 20 */
#define FMT_WHEN_MAX 24 /* 23.09.2026 18:54:01: 19 */
#define FMT_US_MAX FMT_DUR_MAX /* '999 ms' and '59,9 s' take 7 bytes, from a minute on fmt_dur's 15 */
enum { FMT_SEC = 1, FMT_YEAR = 2, FMT_SAMEDAY = 4 };

/* s, min, h, d in both languages (SI symbols), a no-break space before every unit. */
void fmt_dur(uint32_t s, fmt_dur_t mode, char *out, size_t cap);
/* Short spans from microseconds: ms below 1 s (one decimal below 10 ms), seconds with one
 * decimal below a minute ("9,3 s"), then fmt_dur TWO. Rounded half up at every step. */
void fmt_us(uint64_t us, lang_t lang, char *out, size_t cap);
/* The duration between S_AGO_PRE and S_WARN_AGO: "vor 3 min", "3 min ago". */
void fmt_age(uint32_t s, fmt_dur_t mode, lang_t lang, char *out, size_t cap);
/* Local date and time, "23.09. 18:54" / "09-23 18:54"; FMT_YEAR adds the year, FMT_SEC the
 * seconds, FMT_SAMEDAY leaves the date out when ref is on the same local day. False for 0. */
bool fmt_when(uint32_t t, uint32_t ref, unsigned flags, lang_t lang, char *out, size_t cap);
/* The local day of a Unix time in the order of web_day_str. False for 0. */
bool fmt_day(uint32_t t, lang_t lang, char *out, size_t cap);
/* HH:MM:SS of a frame stamp. Before the clock is set the stamp counts from boot, so it
 * reads as seconds with milliseconds ("31536000,999s": 13 bytes). */
void fmt_clock(uint32_t epoch, uint32_t usec, lang_t lang, char *out, size_t cap);
/* "Do, 24.09.2026 <sep> 14:32 MESZ <sep> " for the header and clk, empty while the clock was
 * never set. With &middot; 47 bytes (EN, UTC+3), 59 if a weekday filled its 15 bytes. */
void fmt_clockline(char *out, size_t cap, const char *sep, lang_t lang);

/* B below 1000, then KB, MB, GB, TB to base 1024 with one decimal, the comma on German
 * pages. Plain ASCII: it also goes into JSON and text/plain. 13 bytes at most. */
void fmt_bytes(uint64_t bytes, lang_t lang, char *out, size_t cap);
/* 0..3 decimals rounded half away from zero like JavaScript's toFixed, so a painted value
 * and its poll agree. plus: '+' on a positive non-zero result. 18 bytes below 9e15. */
void fmt_dec(double v, unsigned digits, bool plus, lang_t lang, char *out, size_t cap);
/* Centimetres as metres with one decimal, cut not rounded, and " m". Unsigned inside, so
 * -0,5 m keeps its minus, -0,0 never shows and INT32_MIN negates without overflow. */
#define FMT_ALT_MAX 16 /* "-21474836,4 m" is 13 bytes */
void fmt_alt_cm(int32_t cm, lang_t lang, char *out, size_t cap);

/* The device zone is one of five, stored as its index (CONFIG_INDEX_TIMEZONE). */
#define FMT_ZONE_N 5
#define FMT_ZONE_DEFAULT 2 /* Central Europe, the zone every device had before the setting */

/* Sets TZ for every task. An index out of range falls back to FMT_ZONE_DEFAULT. */
void fmt_tz_set(uint8_t z);
uint8_t fmt_tz(void);
/* "MEZ"/"MESZ" (EN "CET"/"CEST") at t, "UTC" and "UTC+3" as they are. ASCII: also in JSON. */
const char *fmt_tz_abbr(uint32_t t, lang_t lang);
/* Both abbreviations of the device zone, "MEZ/MESZ", or its one designator. */
void fmt_tz_span(lang_t lang, char *out, size_t cap);
/* "Mitteleuropa (MEZ/MESZ)" for zone z, HTML (the names carry entities). 25 bytes at most
 * ("Western Europe (WET/WEST)"). */
void fmt_tz_label(uint8_t z, lang_t lang, char *out, size_t cap);
/* "<script>var ITZ=[3600,1];</script>": the device zone for FMT_ZONE_JS, 35 bytes at most.
 * Returns the length, 0 when it does not fit (the page then counts in Central Europe). */
int fmt_tz_js(char *out, size_t cap);
/* window.itsTz (hm, dm, inp, parse) and window.itsDur, so page scripts count in device time,
 * not browser time. Contains a %: send it as a raw chunk, never through printf. */
extern const char FMT_ZONE_JS[];
