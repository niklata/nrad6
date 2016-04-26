#include <unistd.h>
#include <time.h>
#include <cstdio>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <nk/format.hpp>
#include <nk/scopeguard.hpp>
#include <nk/str_to_int.hpp>
#include <boost/asio.hpp>

#define MAX_LINE 2048

using baia6 = boost::asio::ip::address_v6;
using baia4 = boost::asio::ip::address_v4;

struct lease_state_v4
{
    lease_state_v4(const std::string &ma, int64_t et) : expire_time(et)
    {
        assert(ma.size() == 6);
        for (unsigned i = 0; i < 6; ++i)
            macaddr[i] = ma[i];
    }
    lease_state_v4(const uint8_t *ma, int64_t et) : expire_time(et)
    {
        for (unsigned i = 0; i < 6; ++i)
            macaddr[i] = ma[i];
    }
    uint8_t macaddr[6];
    int64_t expire_time;
};

struct lease_state_v6
{
    lease_state_v6(std::string &&duid_, uint32_t iaid_, int64_t et)
        : duid(std::move(duid_)), iaid(iaid_), expire_time(et) {}
    lease_state_v6(const std::string &duid_, uint32_t iaid_, int64_t et)
        : duid(duid_), iaid(iaid_), expire_time(et) {}
    std::string duid;
    uint32_t iaid;
    int64_t expire_time;
};

// These vectors are sorted by addr.
using dynlease_map_v4 = std::unordered_map<std::string, std::unique_ptr<lease_state_v4>>;
using dynlease_map_v6 = std::unordered_map<std::string, std::unique_ptr<lease_state_v6>>;

// Maps interfaces to lease data.
static std::unordered_map<std::string, dynlease_map_v4> dyn_leases_v4;
static std::unordered_map<std::string, dynlease_map_v6> dyn_leases_v6;

static bool emplace_dynlease_state(size_t linenum, std::string &&interface,
                                   std::string &&v4_addr, const std::string &macaddr,
                                   int64_t expire_time)
{
    auto si = dyn_leases_v4.find(interface);
    if (si == dyn_leases_v4.end()) {
        auto x = dyn_leases_v4.emplace(std::make_pair(std::move(interface), dynlease_map_v4()));
        si = x.first;
    }
    boost::system::error_code ec;
    (void)baia4::from_string(v4_addr, ec);
    if (ec) {
        fmt::print(stderr, "Bad IPv4 address at line {}: {}\n", linenum, v4_addr);
        return false;
    }
    si->second.emplace(std::make_pair(std::move(v4_addr),
                                      std::make_unique<lease_state_v4>(macaddr, expire_time)));
    return true;
}

static bool emplace_dynlease_state(size_t linenum, std::string &&interface,
                                   std::string &&v6_addr, std::string &&duid,
                                   uint32_t iaid, int64_t expire_time)
{
    auto si = dyn_leases_v6.find(interface);
    if (si == dyn_leases_v6.end()) {
        auto x = dyn_leases_v6.emplace(std::make_pair(std::move(interface), dynlease_map_v6()));
        si = x.first;
    }
    boost::system::error_code ec;
    (void)baia6::from_string(v6_addr, ec);
    if (ec) {
        fmt::print(stderr, "Bad IPv6 address at line {}: {}\n", linenum, v6_addr);
        return false;
    }
    si->second.emplace
        (std::make_pair(std::move(v6_addr),
                        std::make_unique<lease_state_v6>(std::move(duid), iaid, expire_time)));
    return true;
}

bool dynlease_add(const std::string &interface, const baia4 &v4_addr, const uint8_t *macaddr,
                  int64_t expire_time)
{
    auto si = dyn_leases_v4.find(interface);
    if (si == dyn_leases_v4.end()) {
        auto x = dyn_leases_v4.emplace(std::make_pair(interface, dynlease_map_v4()));
        si = x.first;
    }

    auto v4s = v4_addr.to_string();
    auto sii = si->second.find(v4s);
    if (sii == si->second.end()) {
        si->second.emplace
            (std::make_pair(std::move(v4s),
                            std::make_unique<lease_state_v4>(macaddr, expire_time)));
        return true;
    } else if (sii->first == v4s && memcmp(&sii->second->macaddr, macaddr, 6) == 0) {
        sii->second->expire_time = expire_time;
        return true;
    }
    return false;
}

bool dynlease_add(const std::string &interface, const baia6 &v6_addr,
                  const std::string &duid, uint32_t iaid, int64_t expire_time)
{
    auto si = dyn_leases_v6.find(interface);
    if (si == dyn_leases_v6.end()) {
        auto x = dyn_leases_v6.emplace(std::make_pair(std::move(interface), dynlease_map_v6()));
        si = x.first;
    }

    auto v6s = v6_addr.to_string();
    auto sii = si->second.find(v6s);
    if (sii == si->second.end()) {
        si->second.emplace
            (std::make_pair(std::move(v6s),
                            std::make_unique<lease_state_v6>(duid, iaid, expire_time)));
        return true;
    } else if (sii->first == v6s && sii->second->duid == duid && sii->second->iaid == iaid) {
        sii->second->expire_time = expire_time;
        return true;
    }
    return false;
}

const std::string &dynlease_query_refresh(const std::string &interface, const uint8_t *macaddr,
                                          int64_t expire_time)
{
    static std::string blank{""};
    auto si = dyn_leases_v4.find(interface);
    if (si == dyn_leases_v4.end()) return blank;

    for (auto &i: si->second) {
        if (memcmp(&i.second->macaddr, macaddr, 6) == 0) {
            i.second->expire_time = expire_time;
            return i.first;
        }
    }
    return blank;
}

const std::string &dynlease_query_refresh(const std::string &interface, const std::string &duid,
                                          uint32_t iaid, int64_t expire_time)
{
    static std::string blank{""};
    auto si = dyn_leases_v6.find(interface);
    if (si == dyn_leases_v6.end()) return blank;

    for (auto &i: si->second) {
        if (i.second->duid == duid && i.second->iaid == iaid) {
            i.second->expire_time = expire_time;
            return i.first;
        }
    }
    return blank;
}

bool dynlease_exists(const std::string &interface, const baia4 &v4_addr, const uint8_t *macaddr)
{
    auto si = dyn_leases_v4.find(interface);
    if (si == dyn_leases_v4.end()) return false;

    const auto v4s = v4_addr.to_string();
    auto sii = si->second.find(v4s);
    if (sii == si->second.end())
        return false;
    else if (sii->first == v4s && memcmp(&sii->second->macaddr, macaddr, 6) == 0) {
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC, &ts))
            throw std::runtime_error("clock_gettime failed");
        return ts.tv_sec < sii->second->expire_time;
    }
    return false;
}

bool dynlease_exists(const std::string &interface, const baia6 &v6_addr,
                     const std::string &duid, uint32_t iaid)
{
    auto si = dyn_leases_v6.find(interface);
    if (si == dyn_leases_v6.end()) return false;

    const auto v6s = v6_addr.to_string();
    auto sii = si->second.find(v6s);
    if (sii == si->second.end())
        return false;
    else if (sii->first == v6s && sii->second->duid == duid && sii->second->iaid == iaid) {
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC, &ts))
            throw std::runtime_error("clock_gettime failed");
        return ts.tv_sec < sii->second->expire_time;
    }
    return false;
}

bool dynlease_del(const std::string &interface, const baia4 &v4_addr, const uint8_t *macaddr)
{
    auto si = dyn_leases_v4.find(interface);
    if (si == dyn_leases_v4.end()) return false;

    const auto v4s = v4_addr.to_string();
    auto sii = si->second.find(v4s);
    if (sii == si->second.end())
        return false;
    else if (sii->first == v4s && memcmp(&sii->second->macaddr, macaddr, 6) == 0) {
        si->second.erase(sii);
        return true;
    }
    return false;
}

bool dynlease_del(const std::string &interface, const baia6 &v6_addr,
                  const std::string &duid, uint32_t iaid)
{
    auto si = dyn_leases_v6.find(interface);
    if (si == dyn_leases_v6.end()) return false;

    const auto v6s = v6_addr.to_string();
    auto sii = si->second.find(v6s);
    if (sii == si->second.end())
        return false;
    else if (sii->first == v6s && sii->second->duid == duid && sii->second->iaid == iaid) {
        si->second.erase(sii);
        return true;
    }
    return false;
}

// v4 <interface> <ip> <macaddr> <expire_time>
// v6 <interface> <ip> <duid> <iaid> <expire_time>

bool dynlease_serialize(const std::string &path)
{
    const auto tmp_path = path + ".tmp";
    const auto f = fopen(tmp_path.c_str(), "w");
    if (!f) {
        fmt::print(stderr, "failed to open '{}' for dynamic lease serialization\n");
        return false;
    }
    SCOPE_EXIT{ fclose(f); unlink(tmp_path.c_str()); };
    std::string wbuf;
    for (const auto &i: dyn_leases_v4) {
        const auto &iface = i.first;
        const auto &ls = i.second;
        for (const auto &j: ls) {
            // Don't write out dynamic leases that have expired.
            struct timespec ts;
            if (clock_gettime(CLOCK_MONOTONIC, &ts))
                throw std::runtime_error("clock_gettime failed");
            if (ts.tv_sec >= j.second->expire_time)
                continue;

            wbuf = fmt::format("v4 {} {} {:02x}{:02x}{:02x}{:02x}{:02x}{:02x} {}\n",
                               iface, j.first,
                               j.second->macaddr[0], j.second->macaddr[1], j.second->macaddr[2],
                               j.second->macaddr[3], j.second->macaddr[4], j.second->macaddr[5],
                               j.second->expire_time);
            const auto fs = fwrite(wbuf.c_str(), wbuf.size(), 1, f);
            if (fs != wbuf.size()) {
                fmt::print(stderr, "{}: short write {} < {}\n", __func__, fs, wbuf.size());
                return false;
            }
        }
    }
    for (const auto &i: dyn_leases_v6) {
        const auto &iface = i.first;
        const auto &ls = i.second;
        for (const auto &j: ls) {
            // Don't write out dynamic leases that have expired.
            struct timespec ts;
            if (clock_gettime(CLOCK_MONOTONIC, &ts))
                throw std::runtime_error("clock_gettime failed");
            if (ts.tv_sec >= j.second->expire_time)
                continue;

            wbuf = fmt::format("v6 {} {} ", iface, j.first);
            for (const auto &k: j.second->duid)
                wbuf.append(fmt::format("{:02x}", k));
            wbuf.append(" {} {}\n", j.second->iaid, j.second->expire_time);
            const auto fs = fwrite(wbuf.c_str(), wbuf.size(), 1, f);
            if (fs != wbuf.size()) {
                fmt::print(stderr, "{}: short write {} < {}\n", __func__, fs, wbuf.size());
                return false;
            }
        }
    }
    if (fflush(f)) {
        fmt::print(stderr, "{}: fflush failed: {}\n", __func__, strerror(errno));
        return false;
    }
    const auto fd = fileno(f);
    if (fdatasync(fd)) {
        fmt::print(stderr, "{}: fdatasync failed: {}\n", __func__, strerror(errno));
        return false;
    }
    if (rename(tmp_path.c_str(), path.c_str())) {
        fmt::print(stderr, "{}: rename failed: {}\n", __func__, strerror(errno));
        return false;
    }
    return true;
}

// v4 <interface> <ip> <macaddr> <expire_time>
// v6 <interface> <ip> <duid> <iaid> <expire_time>

struct cfg_parse_state {
    cfg_parse_state() : st(nullptr), cs(0) {}
    void newline() {
        duid.clear();
        macaddr.clear();
        v4_addr.clear();
        v6_addr.clear();
        interface.clear();
        iaid = 0;
        expire_time = 0;
    }
    const char *st;
    int cs;

    std::string duid;
    std::string macaddr;
    std::string v4_addr;
    std::string v6_addr;
    std::string interface;
    int64_t expire_time;
    uint32_t iaid;
};

%%{
    machine dynlease_line_m;
    access cps.;

    action St { cps.st = p; }

    # XXX: Normalize to lowercase!
    action InterfaceEn { cps.interface = std::string(cps.st, p - cps.st); }
    action DuidEn { cps.duid = std::string(cps.st, p - cps.st); }
    action IaidEn { cps.iaid = nk::str_to_u32(std::string(cps.st, p - cps.st)); }
    action MacAddrEn { cps.macaddr = std::string(cps.st, p - cps.st); }
    action V4AddrEn { cps.v4_addr = std::string(cps.st, p - cps.st); }
    action V6AddrEn { cps.v6_addr = std::string(cps.st, p - cps.st); }
    action ExpireTimeEn { cps.expire_time = nk::str_to_s64(std::string(cps.st, p - cps.st)); }

    action V4EntryEn {
        emplace_dynlease_state(linenum, std::move(cps.interface), std::move(cps.v4_addr),
                               cps.macaddr, cps.expire_time);
    }
    action V6EntryEn {
        emplace_dynlease_state(linenum, std::move(cps.interface), std::move(cps.v6_addr),
                               std::move(cps.duid), cps.iaid, cps.expire_time);
    }

    interface = alnum+ >St %InterfaceEn;
    duid = (xdigit+ | (xdigit{2} ('-' xdigit{2})*)+) >St %DuidEn;
    iaid = digit+ >St %IaidEn;
    macaddr = ((xdigit{2} ':'){5} xdigit{2}) >St %MacAddrEn;
    v4_addr = (digit{1,3} | '.')+ >St %V4AddrEn;
    v6_addr = (xdigit{1,4} | ':')+ >St %V6AddrEn;
    expire_time = digit+ >St %ExpireTimeEn;

    v4_entry = space* 'v4' space+ interface space+ v4_addr space+ macaddr space+ expire_time space*;
    v6_entry = space* 'v6' space+ interface space+ v6_addr space+ duid space+ iaid space+ expire_time space*;

    main := v4_entry %V4EntryEn | v6_entry %V6EntryEn;
}%%

%% write data;

static int do_parse_dynlease_line(cfg_parse_state &cps, const char *p, size_t plen,
                             const size_t linenum)
{
    const char *pe = p + plen;
    const char *eof = pe;

    %% write init;
    %% write exec;

    if (cps.cs >= dynlease_line_m_first_final)
        return 1;
    if (cps.cs == dynlease_line_m_error)
        return -1;
    return -2;
}

bool dynlease_deserialize(const std::string &path)
{
    char buf[MAX_LINE];
    const auto f = fopen(path.c_str(), "r");
    if (!f) {
        fmt::print(stderr, "failed to open '{}' for dynamic lease deserialization\n");
        return false;
    }
    SCOPE_EXIT{ fclose(f); };
    dyn_leases_v4.clear();
    dyn_leases_v6.clear();
    size_t linenum = 0;
    cfg_parse_state ps;
    while (!feof(f)) {
        auto fsv = fgets(buf, sizeof buf, f);
        auto llen = strlen(buf);
        if (buf[llen-1] == '\n')
            buf[--llen] = 0;
        ++linenum;
        if (!fsv) {
            if (!feof(f))
                fmt::print(stderr, "{}: io error fetching line of '{}'\n", __func__, path);
            break;
        }
        if (llen == 0)
            continue;
        ps.newline();
        auto r = do_parse_dynlease_line(ps, buf, llen, linenum);
        if (r < 0) {
            if (r == -2)
                fmt::print(stderr, "{}: Incomplete dynlease at line {}; ignoring\n",
                           __func__, linenum);
            else
                fmt::print(stderr, "{}: Malformed dynlease at line {}; ignoring.\n",
                           __func__, linenum);
            continue;
        }
    }
    return true;
}

