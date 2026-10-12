#include "web_msgdetail_priv.h"

/* Hours from 2 h and minutes from 2 min when exact, seconds otherwise, with a no-break space
 * before the unit (fmt_dur). */
static void add_duration(sb_t *b, uint32_t s)
{
    char d[FMT_DUR_MAX];
    fmt_dur(s, FMT_DUR_EXACT, d, sizeof d);
    sb_add(b, "%s", d);
}

void denm_text(sb_t *b, const msg_extra_t *x, lang_t lang)
{
    if (x->denm_termination == ITS_DENM_TERM_CANCELLATION ||
        x->denm_termination == ITS_DENM_TERM_NEGATION)
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s", S(x->denm_termination == ITS_DENM_TERM_CANCELLATION
                          ? S_DENM_CANCEL : S_DENM_NEGATE));
        item_end(b, m);
    }
    if (x->denm_validity_s)
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s ", S(S_DENM_VALID));
        add_duration(b, x->denm_validity_s);
        if (!x->denm_validity_sent)
            sb_add(b, " (%s)", S(S_DENM_DEFAULT));
        item_end(b, m);
    }
    /* How far from the spot the warning is meant to matter. The steps are fixed, so the
     * distance is printed from the step, not from a number in the message. */
    if (x->denm_aware_dist <= ITS_DENM_DIST_OVER)
    {
        static const char *const STEP[] = { "50 m", "100 m", "200 m", "500 m",
                                            "1 km", "5 km", "10 km" };
        size_t m = item_begin(b, SEP);
        if (x->denm_aware_dist == ITS_DENM_DIST_OVER)
            sb_add(b, "%s", S(S_DENM_DIST_OVER));
        else
            sb_add(b, "%s %s", S(S_DENM_AWARE), STEP[x->denm_aware_dist]);
        item_end(b, m);
    }
    if (x->denm_traffic_dir <= ITS_DENM_DIR_OPPOSITE)
    {
        static const str_id_t DIR[] = { S_DENM_DIR_ALL, S_DENM_DIR_UP,
                                        S_DENM_DIR_DOWN, S_DENM_DIR_OPP };
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s %s", S(S_DENM_DIR), S(DIR[x->denm_traffic_dir]));
        item_end(b, m);
    }
    if (x->denm_road_type <= ITS_DENM_ROAD_RURAL_SEP)
    {
        static const str_id_t ROAD[] = { S_DENM_ROAD_UO, S_DENM_ROAD_US,
                                         S_DENM_ROAD_FO, S_DENM_ROAD_FS };
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s", S(ROAD[x->denm_road_type]));
        item_end(b, m);
    }
    /* InformationQuality counts 1 (lowest) to 7 (highest). 0 means the sender did not say,
     * and "0/7" would read as a judgement it never made. */
    if (x->denm_quality >= 1 && x->denm_quality <= 7)
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s %u/7", S(S_DENM_QUALITY), (unsigned)x->denm_quality);
        item_end(b, m);
    }
    if (x->denm_has_speed)
    {
        /* 0.01 m/s on the wire, and 3.6/100 turns it into km/h. */
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s %u km/h", S(S_DENM_AT_SPEED),
               (unsigned)((x->denm_speed_cms * 36u + 500u) / 1000u));
        item_end(b, m);
    }
    if (x->denm_has_heading)
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s %u&deg;", S(S_DENM_AT_DIR), (unsigned)(x->denm_heading_ddeg / 10));
        item_end(b, m);
    }
    if (x->denm_has_alt)
    {
        char alt[FMT_ALT_MAX];
        fmt_alt_cm(x->denm_alt_cm, lang, alt, sizeof alt);
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s %s", S(S_LBL_ALT), alt);
        item_end(b, m);
    }
    if (x->denm_tx_interval_ms)
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s ", S(S_DENM_REPEAT));
        /* 1..10000 ms by TS 102 894-2, but the 14 bits let up to 16384 through: ms below a
         * second, then seconds with one decimal ("16,4 s" at most). */
        add_us(b, (uint32_t)x->denm_tx_interval_ms * 1000u, lang);
        item_end(b, m);
    }
    /* The points of the first trace as sent (up to 40), not the 8 the decoder keeps. */
    if (x->denm_path_len)
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s %u %s", S(S_DENM_ZONE), (unsigned)x->denm_path_len,
               S(x->denm_path_len == 1 ? S_DENM_POINT : S_DENM_POINTS));
        if (x->denm_n_traces > 1)
            sb_add(b, " (1/%u)", (unsigned)x->denm_n_traces);
        item_end(b, m);
    }
    /* eventZone (eventHistory before 2.x): how far the spot itself reaches. */
    if (x->denm_n_hist)
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s %u %s", S(S_DENM_EXTENT), (unsigned)x->denm_n_hist,
               S(x->denm_n_hist == 1 ? S_DENM_POINT : S_DENM_POINTS));
        item_end(b, m);
    }
    if (x->denm_station_type != ITS_DENM_STATION_NONE)
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s %s", S(S_DENM_STATION), S(web_msgdetail_station_cat(x->denm_station_type)));
        item_end(b, m);
    }
}
