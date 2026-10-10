#include "web_mqtt.h"

#include <stdio.h>

#include "esp_timer.h"

#include "web_fmt.h"
#include "webserver_priv.h"

/* The first try of a boot gets this long before the page calls it a failure. */
#define MQTT_FIRST_TRY_US (60 * 1000000LL)

static const str_id_t WHY[] = {
    [MQTT_WHY_NONE]    = S_COUNT,
    [MQTT_WHY_DNS]     = S_MQTT_WHY_DNS,
    [MQTT_WHY_UNREACH] = S_MQTT_WHY_UNREACH,
    [MQTT_WHY_TLS]     = S_MQTT_WHY_TLS,
    [MQTT_WHY_AUTH]    = S_MQTT_WHY_AUTH,
    [MQTT_WHY_REFUSED] = S_MQTT_WHY_REFUSED,
    [MQTT_WHY_LOST]    = S_MQTT_WHY_LOST,
    [MQTT_WHY_NONET]   = S_MQTT_WHY_NONET,
};
_Static_assert(sizeof(WHY) / sizeof(WHY[0]) == MQTT_WHY_COUNT, "one text per reason");

/* Worst 67 bytes: "mit " and a host of 63. */
void web_mqtt_target(const mqtt_state_t *s, char *out, size_t cap)
{
    if (!cap)
        return;
    out[0] = '\0';
    if (s->host[0])
        snprintf(out, cap, T(S_MQTT_TO), s->host);
}

/* Worst 87 bytes with &middot;, 81 with the raw dot (German: never connected, login refused). */
void web_mqtt_detail(const mqtt_state_t *s, const char *sep, char *out, size_t cap)
{
    if (!cap)
        return;
    out[0] = '\0';
    int64_t now = esp_timer_get_time();
    if (s->connected || (!s->ever && s->why == MQTT_WHY_NONE && now < MQTT_FIRST_TRY_US))
        return;
    int n;
    if (s->ever)
    {
        char dur[FMT_DUR_MAX];
        uint64_t d = (uint64_t)((now - s->since_us) / 1000000);
        fmt_dur(d > UINT32_MAX ? UINT32_MAX : (uint32_t)d, FMT_DUR_TWO, dur, sizeof dur);
        n = snprintf(out, cap, T(S_MQTT_SINCE), dur);
    }
    else
        n = snprintf(out, cap, "%s", T(S_MQTT_NEVER));
    if (s->why != MQTT_WHY_NONE && s->why < MQTT_WHY_COUNT)
        web_addf(out, cap, n, " %s %s", sep, T(WHY[s->why]));
}

/* Worst 218 bytes (German): state word, target and detail line. Down is amber like the
 * fault bar's MQTT line: a warning, not an alarm. */
void web_mqtt_state_cell(char *out, size_t cap)
{
    mqtt_state_t s;
    mqtt_get_state(&s);
    char tgt[96], det[160];
    web_mqtt_target(&s, tgt, sizeof(tgt));
    web_mqtt_detail(&s, "&middot;", det, sizeof(det));
    int n = web_addf(out, cap, 0, "<span class='%s'>%s</span>", s.connected ? "v-ok" : "v-warn",
                     T(s.connected ? S_CONNECTED : S_DISCONNECTED));
    if (tgt[0])
        n = web_addf(out, cap, n, " &middot; %s", tgt);
    if (det[0])
        web_addf(out, cap, n, "<br><small>%s</small>", det);
}
