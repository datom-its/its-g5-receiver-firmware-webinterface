#include "web_msgdetail_priv.h"

str_id_t role_name(uint8_t role)
{
    static const str_id_t ROLES[24] = {
        S_SREM_VEHICLE, S_BVR_PUBLIC, S_BVR_SPECIAL, S_BVR_DANGEROUS,
        S_BVR_ROADWORK, S_BVR_RESCUE, S_BVR_EMERGENCY, S_BVR_SAFETYCAR,
        S_UNKNOWN, S_BVR_TRUCK, S_BVR_MOTORCYCLE, S_BVR_ROADSIDE,
        S_BVR_POLICE, S_BVR_FIRE, S_BVR_AMBULANCE, S_BVR_DOT,
        S_BVR_TRANSIT, S_BVR_SLOW, S_BVR_STOPNGO, S_BVR_CYCLIST,
        S_DIR_PED, S_BVR_NONMOTOR, S_BVR_MILITARY, S_BVR_TRAM,
    };
    return role < 24 ? ROLES[role] : S_BVR_OTHER;
}

static void add_intersection(sb_t *b, const msg_prio_item_t *it)
{
    if (it->has_region)
        sb_add(b, "%u/%u", (unsigned)it->region, (unsigned)it->id);
    else
        sb_add(b, "%u", (unsigned)it->id);
}

/* A lane or approach 0 means the intersection itself. */
static void add_access(sb_t *b, const its_srem_access_t *a, lang_t lang)
{
    switch (a->kind)
    {
    case ITS_SREM_AP_LANE:
    case ITS_SREM_AP_APPROACH:
        if (a->value == 0)
            sb_add(b, "%s", S(S_AP_CENTER));
        else
            sb_add(b, "%s %u", S(a->kind == ITS_SREM_AP_LANE ? S_AP_LANE : S_AP_APPROACH),
                   (unsigned)a->value);
        break;
    case ITS_SREM_AP_CONNECTION:
        sb_add(b, "%s %u", S(S_AP_CONNECTION), (unsigned)a->value);
        break;
    default:
        sb_add(b, "%s", S(S_AP_OTHER));
        break;
    }
}

static void add_requester(sb_t *b, uint8_t kind, uint32_t id, lang_t lang)
{
    if (kind == ITS_SREM_ID_STATION)
        sb_add(b, "%s %lu", S(S_SREM_VEHICLE), (unsigned long)id);
    else
        sb_add(b, "%s %08lx", S(S_SREM_ENTITY), (unsigned long)id);
}

static str_id_t request_type_name(uint8_t code);
static str_id_t status_name(uint8_t code);

str_id_t web_msgdetail_prio_code(uint8_t kind, uint8_t code)
{
    return kind == 9 ? request_type_name(code) : status_name(code);
}

str_id_t web_msgdetail_prio_role(uint8_t role)
{
    return role_name(role);
}

/* Lane, approach or connection: which kind of access point the number means. Same words
 * as add_access() above, so the log and the message detail read alike. */
str_id_t web_msgdetail_prio_access(uint8_t kind)
{
    switch (kind)
    {
    case ITS_SREM_AP_LANE:       return S_AP_LANE;
    case ITS_SREM_AP_APPROACH:   return S_AP_APPROACH;
    case ITS_SREM_AP_CONNECTION: return S_AP_CONNECTION;
    default:                     return S_AP_OTHER;
    }
}

static str_id_t request_type_name(uint8_t code)
{
    switch (code)
    {
    case 1:  return S_PRT_REQUEST;
    case 2:  return S_PRT_UPDATE;
    case 3:  return S_PRT_CANCEL;
    default: return S_PRT_UNKNOWN;
    }
}

static str_id_t status_name(uint8_t code)
{
    switch (code)
    {
    case 0:  return S_UNKNOWN;
    case 1:  return S_SSEM_ST_REQUESTED;
    case 2:  return S_SSEM_ST_PROCESSING;
    case 3:  return S_SSEM_ST_WATCH;
    case 4:  return S_SSEM_ST_GRANTED;
    case 5:  return S_SSEM_ST_REJECTED;
    case 6:  return S_SSEM_ST_MAXPRESENCE;
    case 7:  return S_SSEM_ST_LOCKED;
    default: return S_SSEM_ST_OTHER;
    }
}

/* One item per request or answer: intersection, what, and the details in a parenthesis. */
void prio_text(sb_t *b, const msg_prio_t *p, lang_t lang)
{
    bool srem = p->message_id == 9;
    for (uint8_t i = 0; i < p->n_items && i < MSG_PRIO_ITEMS; i++)
    {
        const msg_prio_item_t *it = &p->item[i];
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s ", S(srem ? S_SREM_AT : S_SSEM_AT));
        add_intersection(b, it);
        sb_add(b, ": %s", S(srem ? request_type_name(it->code) : status_name(it->code)));
        const char *next = " (";
        bool with_request = srem || it->requester_kind != ITS_SREM_ID_NONE;
        if (!srem && with_request)
        {
            sb_add(b, "%s", next);
            add_requester(b, it->requester_kind, it->requester_id, lang);
            next = ", ";
        }
        if (with_request)
        {
            sb_add(b, "%s%s %u", next, S(S_SREM_REQ_NO), (unsigned)it->request_id);
            next = ", ";
        }
        if (it->in.kind != ITS_SREM_AP_NONE || it->out.kind != ITS_SREM_AP_NONE)
        {
            sb_add(b, "%s", next);
            next = ", ";
            if (it->in.kind != ITS_SREM_AP_NONE)
                add_access(b, &it->in, lang);
            if (it->out.kind != ITS_SREM_AP_NONE)
            {
                sb_add(b, "%s", it->in.kind != ITS_SREM_AP_NONE ? " &rarr; " : "&rarr; ");
                add_access(b, &it->out, lang);
            }
        }
        if (next[0] == ',')
            sb_add(b, ")");
        item_end(b, m);
    }
    if (p->more)
    {
        size_t m = item_begin(b, " ");
        sb_add(b, "&hellip; %s", S(S_MORE));
        item_end(b, m);
    }
    if (!srem)
        return;
    if (p->has_role)
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s: %s", S(S_SREM_ROLE), S(role_name(p->role)));
        item_end(b, m);
    }
    if (p->requestor_kind == ITS_SREM_ID_STATION || p->requestor_kind == ITS_SREM_ID_ENTITY)
    {
        size_t m = item_begin(b, SEP);
        add_requester(b, p->requestor_kind, p->requestor_id, lang);
        item_end(b, m);
    }
    if (p->name[0])
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s: ", S(S_SREM_NAME));
        add_escaped(b, p->name);
        item_end(b, m);
    }
    if (p->route[0])
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s: ", S(S_SREM_ROUTE));
        add_escaped(b, p->route);
        item_end(b, m);
    }
}
