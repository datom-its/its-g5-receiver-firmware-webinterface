#include "web_fmt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* U+00A0: keeps "12 min" whole on a phone line, and is valid in HTML, JSON and textContent. */
#define NBSP "\xC2\xA0"

/* Complete or empty: snprintf cuts anywhere, also between the two bytes of NBSP. */
static void fit(char *out, size_t cap, int k)
{
    if (k < 0 || (size_t)k >= cap)
        out[0] = '\0';
}

void fmt_dur(uint32_t s, fmt_dur_t mode, char *out, size_t cap)
{
    /* Where TWO, ONE and PHASE step up to days, hours and minutes. */
    static const uint32_t STEP[3][3] = {
        [FMT_DUR_TWO] = { 86400, 3600, 60 },
        [FMT_DUR_ONE] = { 172800, 7200, 120 },
        [FMT_DUR_PHASE] = { 172800, 7200, 180 },
    };
    static const uint32_t UNIT[4] = { 86400, 3600, 60, 1 };
    static const char *const SYM[4] = { "d", "h", "min", "s" };
    unsigned i = 0;
    int k;

    if (!out || !cap)
        return;
    if (mode == FMT_DUR_EXACT)
        i = s >= 7200 && s % 3600 == 0 ? 1 : s >= 120 && s % 60 == 0 ? 2 : 3;
    else
    {
        const uint32_t *st = STEP[(unsigned)mode < 3 ? mode : FMT_DUR_TWO];
        while (i < 3 && s < st[i])
            i++;
    }
    if (mode == FMT_DUR_EXACT || mode == FMT_DUR_ONE || i == 3)
        k = snprintf(out, cap, "%lu" NBSP "%s", (unsigned long)(s / UNIT[i]), SYM[i]);
    else
        k = snprintf(out, cap, "%lu" NBSP "%s" NBSP "%lu" NBSP "%s", (unsigned long)(s / UNIT[i]),
                     SYM[i], (unsigned long)(s % UNIT[i] / UNIT[i + 1]), SYM[i + 1]);
    fit(out, cap, k);
}

void fmt_age(uint32_t s, fmt_dur_t mode, lang_t lang, char *out, size_t cap)
{
    char d[FMT_DUR_MAX];
    const char *pre = web_str(S_AGO_PRE, lang), *post = web_str(S_WARN_AGO, lang);

    if (!out || !cap)
        return;
    fmt_dur(s, mode, d, sizeof(d));
    /* Each language fills one half of the pair, the empty one takes no space. */
    int k = snprintf(out, cap, "%s%s%s%s%s", pre, pre[0] ? NBSP : "", d, post[0] ? NBSP : "", post);
    fit(out, cap, k);
}

void fmt_us(uint64_t us, lang_t lang, char *out, size_t cap)
{
    char sep = lang == LANG_DE ? ',' : '.';
    uint64_t t;
    int k;

    if (!out || !cap)
        return;
    /* fmt_dur counts in 32-bit seconds. The clamp also keeps the rounding sums below 2^64. */
    if (us > (uint64_t)UINT32_MAX * 1000000u)
        us = (uint64_t)UINT32_MAX * 1000000u;
    /* Each step on the rounded value, so 999,5 ms reads 1,0 s and never 1000 ms. */
    if ((t = (us + 50) / 100) < 100)
        k = snprintf(out, cap, "%u%c%u" NBSP "ms", (unsigned)(t / 10), sep, (unsigned)(t % 10));
    else if ((t = (us + 500) / 1000) < 1000)
        k = snprintf(out, cap, "%u" NBSP "ms", (unsigned)t);
    else if ((t = (us + 50000) / 100000) < 600)
        k = snprintf(out, cap, "%u%c%u" NBSP "s", (unsigned)(t / 10), sep, (unsigned)(t % 10));
    else
    {
        fmt_dur((uint32_t)((us + 500000) / 1000000), FMT_DUR_TWO, out, cap);
        return;
    }
    fit(out, cap, k);
}

bool fmt_when(uint32_t t, uint32_t ref, unsigned flags, lang_t lang, char *out, size_t cap)
{
    struct tm lt, rt;
    time_t u = (time_t)t, r = (time_t)ref;
    bool sec = (flags & FMT_SEC) != 0, year = (flags & FMT_YEAR) != 0;
    size_t n;

    if (!out || !cap)
        return false;
    out[0] = '\0';
    if (!t || !localtime_r(&u, &lt))
        return false;
    /* Literal formats in every branch: GCC checks each one, a table of formats it cannot. */
    if ((flags & FMT_SAMEDAY) && localtime_r(&r, &rt) && rt.tm_year == lt.tm_year &&
        rt.tm_yday == lt.tm_yday)
        n = strftime(out, cap, sec ? "%H:%M:%S" : "%H:%M", &lt);
    else if (lang == LANG_DE)
        n = strftime(out, cap,
                     year ? (sec ? "%d.%m.%Y %H:%M:%S" : "%d.%m.%Y %H:%M")
                          : (sec ? "%d.%m. %H:%M:%S" : "%d.%m. %H:%M"),
                     &lt);
    else
        n = strftime(out, cap,
                     year ? (sec ? "%Y-%m-%d %H:%M:%S" : "%Y-%m-%d %H:%M")
                          : (sec ? "%m-%d %H:%M:%S" : "%m-%d %H:%M"),
                     &lt);
    /* strftime leaves the buffer unspecified when the text does not fit. */
    if (!n)
        out[0] = '\0';
    return n != 0;
}

bool fmt_day(uint32_t t, lang_t lang, char *out, size_t cap)
{
    struct tm lt;
    time_t u = (time_t)t;

    if (!out || !cap)
        return false;
    out[0] = '\0';
    if (!t || !localtime_r(&u, &lt))
        return false;
    if (!strftime(out, cap, lang == LANG_DE ? "%d.%m.%Y" : "%Y-%m-%d", &lt))
    {
        out[0] = '\0';
        return false;
    }
    return true;
}

void fmt_clock(uint32_t epoch, uint32_t usec, lang_t lang, char *out, size_t cap)
{
    int k;

    if (!out || !cap)
        return;
    /* Before NTP the sniffer stamps seconds since boot (< 1 year), which no clock face shows. */
    if (epoch > 31536000)
    {
        time_t t = (time_t)epoch;
        struct tm lt;
        if (!localtime_r(&t, &lt))
        {
            out[0] = '\0';
            return;
        }
        k = snprintf(out, cap, "%02d:%02d:%02d", lt.tm_hour, lt.tm_min, lt.tm_sec);
    }
    else
        k = snprintf(out, cap, "%lu%s%03lus", (unsigned long)epoch, lang == LANG_DE ? "," : ".",
                     (unsigned long)(usec / 1000));
    fit(out, cap, k);
}

/* A table, because picolibc (CONFIG_LIBC_PICOLIBC) has no tm_gmtoff to hand the offset to the
 * browser, and its %Z says CEST, never MESZ. */
typedef struct
{
    const char *posix;
    int32_t std_s;          /* standard offset east of UTC, for the browser */
    bool eu_dst;            /* summer time from the last Sunday of March to that of October */
    str_id_t name, ab_std, ab_dst; /* S_COUNT: no text of its own */
    const char *ab_fix;     /* designator of a zone without summer time, the same in both languages */
} fmt_zone_t;

/* The three summer-time rules all switch at 01:00 UTC, the one rule FMT_ZONE_JS knows. */
static const fmt_zone_t ZONES[FMT_ZONE_N] = {
    { "UTC0", 0, false, S_TZ_N_UTC, S_COUNT, S_COUNT, "UTC" },
    { "WET0WEST,M3.5.0/1,M10.5.0", 0, true, S_TZ_N_WET, S_TZ_AB_WET, S_TZ_AB_WEST, NULL },
    { "CET-1CEST,M3.5.0,M10.5.0/3", 3600, true, S_TZ_N_CET, S_TZ_AB_CET, S_TZ_AB_CEST, NULL },
    { "EET-2EEST,M3.5.0/3,M10.5.0/4", 7200, true, S_TZ_N_EET, S_TZ_AB_EET, S_TZ_AB_EEST, NULL },
    { "TRT-3", 10800, false, S_TZ_N_TRT, S_COUNT, S_COUNT, "UTC+3" },
};
_Static_assert(FMT_ZONE_DEFAULT < FMT_ZONE_N, "the default zone must be in the table");

/* One byte, written at boot and by the httpd task (settings, import): readers see old or new. */
static uint8_t cur_zone = FMT_ZONE_DEFAULT;

static const char *zone_abbr(const fmt_zone_t *z, bool dst, lang_t lang)
{
    str_id_t id = dst ? z->ab_dst : z->ab_std;
    if (z->ab_fix)
        return z->ab_fix;
    return id < S_COUNT ? web_str(id, lang) : "";
}

static void zone_span(const fmt_zone_t *z, lang_t lang, char *out, size_t cap)
{
    int k = z->ab_fix ? snprintf(out, cap, "%s", z->ab_fix)
                      : snprintf(out, cap, "%s/%s", zone_abbr(z, false, lang), zone_abbr(z, true, lang));
    fit(out, cap, k);
}

void fmt_tz_set(uint8_t z)
{
    if (z >= FMT_ZONE_N)
        z = FMT_ZONE_DEFAULT;
    setenv("TZ", ZONES[z].posix, 1);
    tzset();
    cur_zone = z;
}

uint8_t fmt_tz(void)
{
    return cur_zone;
}

const char *fmt_tz_abbr(uint32_t t, lang_t lang)
{
    struct tm lt;
    time_t u = (time_t)t;
    const fmt_zone_t *z = &ZONES[cur_zone];

    if (z->ab_fix)
        return z->ab_fix;
    return localtime_r(&u, &lt) ? zone_abbr(z, lt.tm_isdst > 0, lang) : "";
}

void fmt_tz_span(lang_t lang, char *out, size_t cap)
{
    if (!out || !cap)
        return;
    zone_span(&ZONES[cur_zone], lang, out, cap);
}

void fmt_tz_label(uint8_t z, lang_t lang, char *out, size_t cap)
{
    char span[16]; /* "MEZ/MESZ", "WET/WEST": 8 at most */

    if (!out || !cap)
        return;
    if (z >= FMT_ZONE_N)
        z = FMT_ZONE_DEFAULT;
    zone_span(&ZONES[z], lang, span, sizeof(span));
    fit(out, cap, snprintf(out, cap, "%s (%s)", web_str(ZONES[z].name, lang), span));
}

int fmt_tz_js(char *out, size_t cap)
{
    const fmt_zone_t *z = &ZONES[cur_zone];

    if (!out || !cap)
        return 0;
    int k = snprintf(out, cap, "<script>var ITZ=[%ld,%d];</script>", (long)z->std_s, z->eu_dst ? 1 : 0);
    fit(out, cap, k);
    return out[0] ? k : 0;
}

/* The same rule as ZONES in the browser: standard offset plus an hour between the last
 * Sundays of March and October at 01:00 UTC, computed with getUTC* only, so the zone the
 * browser runs in never counts. itsDur(s, 0|1|2) writes fmt_dur TWO|ONE|PHASE. itsTz.hm and
 * dm match fmt_when. inp and parse fill and read datetime-local fields in device time. */
const char FMT_ZONE_JS[] =
    "<script>(function(){var Z=window.ITZ||[3600,1],de=document.documentElement.lang!=='en',"
    "N='\\u00a0';function p(n){return (n<10?'0':'')+n;}"
    "function ls(y,m){var d=new Date(Date.UTC(y,m+1,0));"
    "return Date.UTC(y,m,d.getUTCDate()-d.getUTCDay(),1);}"
    "function off(ms){var y=new Date(ms).getUTCFullYear();"
    "return (Z[0]+(Z[1]&&ms>=ls(y,2)&&ms<ls(y,9)?3600:0))*1000;}"
    "function w(ms){return new Date(ms+off(ms));}"
    "window.itsDur=function(s,m){var U=[86400,3600,60,1],L=['d','h','min','s'],"
    "T=m===1?[172800,7200,120]:m===2?[172800,7200,180]:[86400,3600,60],i;"
    "s=Math.max(0,Math.floor(+s||0));for(i=0;i<3&&s<T[i];i++);"
    "var r=Math.floor(s/U[i])+N+L[i];"
    "if(m!==1&&i<3)r+=N+Math.floor(s%U[i]/U[i+1])+N+L[i+1];return r;};"
    "window.itsTz={hm:function(ms,sec){var d=w(ms);"
    "return p(d.getUTCHours())+':'+p(d.getUTCMinutes())+(sec?':'+p(d.getUTCSeconds()):'');},"
    "dm:function(ms){var d=w(ms),a=p(d.getUTCDate()),b=p(d.getUTCMonth()+1);"
    "return de?a+'.'+b+'.':b+'-'+a;},"
    "inp:function(ms){var d=w(ms);return d.getUTCFullYear()+'-'+p(d.getUTCMonth()+1)+'-'+"
    "p(d.getUTCDate())+'T'+p(d.getUTCHours())+':'+p(d.getUTCMinutes());},"
    "parse:function(v){var m=/^(\\d{4})-(\\d\\d)-(\\d\\d)T(\\d\\d):(\\d\\d)/.exec(v||'');"
    "if(!m)return 0;var l=Date.UTC(+m[1],m[2]-1,+m[3],+m[4],+m[5]);"
    "return Math.floor((l-off(l-Z[0]*1000))/1000);}};})();</script>";

void fmt_clockline(char *out, size_t cap, const char *sep, lang_t lang)
{
    struct tm lt;
    time_t now = time(NULL);
    char dbuf[16] = "";
    int k;

    if (!out || !cap)
        return;
    out[0] = '\0';
    /* Same threshold the rest of the tree uses for "the clock is real". */
    if (now < 1600000000 || !localtime_r(&now, &lt))
        return;
    if (!sep)
        sep = "";
    /* Weekday short names come from the traffic page's list, so this line needs no
     * vocabulary of its own. */
    const char *day = web_str(S_TRF_WDAYS, lang);
    for (int i = 0; i < lt.tm_wday && day; i++)
    {
        const char *c = strchr(day, ',');
        day = c ? c + 1 : NULL;
    }
    if (day)
    {
        size_t n = 0;
        while (day[n] && day[n] != ',' && n + 1 < sizeof(dbuf))
        {
            dbuf[n] = day[n];
            n++;
        }
        dbuf[n] = '\0';
    }
    /* The zone from the same tm, so the abbreviation cannot come from the second after. */
    const char *ab = zone_abbr(&ZONES[cur_zone], lt.tm_isdst > 0, lang);
    /* dd.mm.yyyy only in German. For English readers a numeric day and month are ambiguous,
     * so English gets yyyy-mm-dd. Two literal formats, not a swapped argument list, so GCC
     * checks both. */
    if (lang == LANG_DE)
        k = snprintf(out, cap, "%s%s%02d.%02d.%04d %s %02d:%02d%s%s %s ", dbuf, dbuf[0] ? ", " : "",
                     lt.tm_mday, lt.tm_mon + 1, lt.tm_year + 1900, sep, lt.tm_hour, lt.tm_min,
                     ab[0] ? NBSP : "", ab, sep);
    else
        k = snprintf(out, cap, "%s%s%04d-%02d-%02d %s %02d:%02d%s%s %s ", dbuf, dbuf[0] ? ", " : "",
                     lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday, sep, lt.tm_hour, lt.tm_min,
                     ab[0] ? NBSP : "", ab, sep);
    fit(out, cap, k);
}

void fmt_bytes(uint64_t bytes, lang_t lang, char *out, size_t cap)
{
    static const char *const UNIT[] = { "KB", "MB", "GB", "TB" };
    uint64_t div = 1024, t;
    unsigned k = 0;
    int w;

    if (!out || !cap)
        return;
    if (bytes < 1000)
        w = snprintf(out, cap, "%u B", (unsigned)bytes);
    else
    {
        /* One family on every page, base 1024 like the settings' MB. Tenths without floating
         * point. The next unit starts at 1000, so no value shows more than three digits before
         * the comma (1003 MiB reads 1,0 GB). */
        for (;;)
        {
            t = bytes / div * 10 + ((bytes % div) * 10 + div / 2) / div;
            if (t < 10000 || k == 3)
                break;
            div <<= 10;
            k++;
        }
        w = snprintf(out, cap, "%llu%c%u %s", (unsigned long long)(t / 10), lang == LANG_DE ? ',' : '.',
                     (unsigned)(t % 10), UNIT[k]);
    }
    fit(out, cap, w);
}

void fmt_dec(double v, unsigned digits, bool plus, lang_t lang, char *out, size_t cap)
{
    static const uint32_t P10[] = { 1, 10, 100, 1000 };
    char sep = lang == LANG_DE ? ',' : '.';
    int k;

    if (!out || !cap)
        return;
    if (digits > 3)
        digits = 3;
    bool neg = v < 0;
    /* Half away from zero on the magnitude, as toFixed does. printf would round half to even
     * and repaint 46,3 as 46,2 on the next poll. */
    double m = (neg ? -v : v) * (double)P10[digits] + 0.5;
    if (!(m < 9.0e15))
    {
        /* Near 2^53 a double has no fraction left to round; also NaN and infinity. */
        k = plus ? snprintf(out, cap, "%+.*f", (int)digits, v) : snprintf(out, cap, "%.*f", (int)digits, v);
        fit(out, cap, k);
        char *d = strchr(out, '.');
        if (d)
            *d = sep;
        return;
    }
    uint64_t t = (uint64_t)m;
    /* The sign only on a non-zero result, so no "-0,0". */
    const char *sg = t == 0 ? "" : neg ? "-" : plus ? "+" : "";
    if (!digits)
        k = snprintf(out, cap, "%s%llu", sg, (unsigned long long)t);
    else
        k = snprintf(out, cap, "%s%llu%c%0*llu", sg, (unsigned long long)(t / P10[digits]), sep, (int)digits,
                     (unsigned long long)(t % P10[digits]));
    fit(out, cap, k);
}

void fmt_alt_cm(int32_t cm, lang_t lang, char *out, size_t cap)
{
    if (!out || !cap)
        return;
    uint32_t a = cm < 0 ? 0u - (uint32_t)cm : (uint32_t)cm;
    /* The minus only from 0,1 m on: a cut -0,05 m would read "-0,0 m". */
    fit(out, cap, snprintf(out, cap, "%s%lu%c%u m", cm < 0 && a >= 10 ? "-" : "",
                           (unsigned long)(a / 100), lang == LANG_DE ? ',' : '.',
                           (unsigned)(a / 10 % 10)));
}
