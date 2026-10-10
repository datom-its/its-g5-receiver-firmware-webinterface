#include "settings_json.h"

#include <climits>
#include <cstring>

#include "ArduinoJson.h"

namespace {

/* Hands the input to ArduinoJson byte by byte and remembers how far it read,
 * so bytes after the closing brace can be refused. */
class CountingReader {
public:
    CountingReader(const char *p, size_t n) : p_(p), n_(n) {}

    int read()
    {
        return pos_ < n_ ? (unsigned char)p_[pos_++] : -1;
    }

    size_t readBytes(char *buf, size_t len)
    {
        size_t k = n_ - pos_ < len ? n_ - pos_ : len;
        memcpy(buf, p_ + pos_, k);
        pos_ += k;
        return k;
    }

    bool only_space_left() const
    {
        for (size_t i = pos_; i < n_; i++)
            if (p_[i] != ' ' && p_[i] != '\t' && p_[i] != '\r' && p_[i] != '\n')
                return false;
        return true;
    }

private:
    const char *p_;
    size_t n_;
    size_t pos_ = 0;
};

void fill(sj_member_t &m, JsonPairConst kv)
{
    memset(&m, 0, sizeof(m));
    JsonString k = kv.key();
    size_t kn = k.size();
    /* A key with a NUL in it cannot match any setting, so it counts as cut. */
    m.key_cut = kn >= SJ_KEY_LEN || memchr(k.c_str(), '\0', kn) != nullptr;
    if (kn >= SJ_KEY_LEN)
        kn = SJ_KEY_LEN - 1;
    memcpy(m.key, k.c_str(), kn);
    m.key[kn] = '\0';

    JsonVariantConst v = kv.value();
    if (v.isNull())
        m.type = SJ_NULL;
    else if (v.is<bool>())
    {
        m.type = SJ_BOOL;
        m.b = v.as<bool>();
    }
    else if (v.is<long long>())
    {
        m.type = SJ_INT;
        m.num = v.as<long long>();
    }
    else if (v.is<unsigned long long>())
    {
        /* Too big for long long, but still a whole number, so it fails the range check. */
        m.type = SJ_INT;
        m.num = LLONG_MAX;
    }
    else if (v.is<double>())
        m.type = SJ_FLOAT;
    else if (v.is<JsonString>())
    {
        m.type = SJ_STR;
        JsonString s = v.as<JsonString>();
        size_t sn = s.size();
        m.str_nul = memchr(s.c_str(), '\0', sn) != nullptr;
        m.str_cut = sn >= SJ_STR_LEN;
        if (sn >= SJ_STR_LEN)
            sn = SJ_STR_LEN - 1;
        memcpy(m.str, s.c_str(), sn);
        m.str[sn] = '\0';
    }
    else if (v.is<JsonArrayConst>())
        m.type = SJ_ARRAY;
    else
        m.type = SJ_OBJECT;
}

/* Keys and strings go in as const char *. A char array would be taken as a
 * literal of its full size, NUL padding included, and stored by pointer. */
void put(JsonObject obj, const sj_member_t &m)
{
    const char *key = m.key;
    switch (m.type)
    {
    case SJ_NULL:  obj[key] = nullptr; break;
    case SJ_BOOL:  obj[key] = m.b; break;
    case SJ_INT:   obj[key] = m.num; break;
    case SJ_STR:   obj[key] = static_cast<const char *>(m.str); break;
    default:       break;
    }
}

} // namespace

extern "C" sj_parse_t settings_json_parse(const char *json, size_t len,
                                         sj_member_t *top, size_t top_cap, size_t *top_n,
                                         sj_member_t *set, size_t set_cap, size_t *set_n)
{
    *top_n = 0;
    *set_n = 0;
    if (!json || len == 0)
        return SJ_PARSE_EMPTY;

    JsonDocument doc;
    CountingReader rd(json, len);
    /* Four nested levels: the file, "settings" and two more, so a stray array or object
     * inside "settings" is reported as a wrong value instead of failing the whole file. */
    DeserializationError err = deserializeJson(doc, rd, DeserializationOption::NestingLimit(4));
    switch (err.code())
    {
    case DeserializationError::Ok:         break;
    case DeserializationError::EmptyInput: return SJ_PARSE_EMPTY;
    case DeserializationError::NoMemory:   return SJ_PARSE_NOMEM;
    default:                               return SJ_PARSE_SYNTAX;
    }
    if (!rd.only_space_left())
        return SJ_PARSE_SYNTAX;
    if (!doc.is<JsonObjectConst>())
        return SJ_PARSE_NOT_OBJECT;

    JsonObjectConst root = doc.as<JsonObjectConst>();
    for (JsonPairConst kv : root)
    {
        if (*top_n >= top_cap)
            return SJ_PARSE_TOO_MANY;
        fill(top[(*top_n)++], kv);
    }
    JsonObjectConst s = root["settings"];
    if (s)
    {
        for (JsonPairConst kv : s)
        {
            if (*set_n >= set_cap)
                return SJ_PARSE_TOO_MANY;
            fill(set[(*set_n)++], kv);
        }
    }
    return SJ_PARSE_OK;
}

extern "C" size_t settings_json_write(const sj_member_t *top, size_t top_n,
                                     const sj_member_t *set, size_t set_n,
                                     char *out, size_t cap)
{
    JsonDocument doc;
    JsonObject root = doc.to<JsonObject>();
    for (size_t i = 0; i < top_n; i++)
        put(root, top[i]);
    JsonObject s = root["settings"].to<JsonObject>();
    for (size_t i = 0; i < set_n; i++)
        put(s, set[i]);
    if (doc.overflowed() || !cap)
        return 0;
    size_t need = measureJsonPretty(doc);
    if (need + 1 > cap)
        return 0;
    size_t n = serializeJsonPretty(doc, out, cap);

    /* ArduinoJson escapes \b \f \n \r \t in strings but writes other control characters
     * raw, which JSON forbids. Outside strings the indented output holds only CR LF. */
    size_t extra = 0;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)out[i] < 0x20 && out[i] != '\r' && out[i] != '\n')
            extra += 5;
    if (n + extra + 1 > cap)
        return 0;
    out[n + extra] = '\0';
    for (size_t i = n, o = n + extra; i-- > 0; )
    {
        unsigned char c = (unsigned char)out[i];
        if (c < 0x20 && c != '\r' && c != '\n')
        {
            static const char hex[] = "0123456789abcdef";
            o -= 6;
            memcpy(out + o, "\\u00", 4);
            out[o + 4] = hex[c >> 4];
            out[o + 5] = hex[c & 15];
        }
        else
            out[--o] = (char)c;
    }
    return n + extra;
}
