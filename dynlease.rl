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
    lease_state_v4(baia4 &&a4, const std::string &ma, int64_t et)
        : addr(std::move(a4)), expire_time(et)
    {
        assert(ma.size() == 6);
        for (unsigned i = 0; i < 6; ++i)
            macaddr[i] = ma[i];
    }
    baia4 addr;
    uint8_t macaddr[6];
    int64_t expire_time;
};

struct lease_state_v6
{
    lease_state_v6(baia6 &&a6, std::string &&duid_, uint32_t iaid_, int64_t et)
        : addr(std::move(a6)), duid(std::move(duid_)), iaid(iaid_), expire_time(et) {}
    baia6 addr;
    std::string duid;
    uint32_t iaid;
    int64_t expire_time;
};

// These vectors are sorted by addr.
using dynlease_map_v4 = std::vector<lease_state_v4>;
using dynlease_map_v6 = std::vector<lease_state_v6>;

// Maps interfaces to lease data.
static std::unordered_map<std::string, dynlease_map_v4> dyn_leases_v4;
static std::unordered_map<std::string, dynlease_map_v6> dyn_leases_v6;

bool emplace_dynlease_state(size_t linenum, std::string &&interface,
                            const std::string &v4_addr, std::string &&macaddr,
                            int64_t expire_time, bool do_sort)
{
    auto si = dyn_leases_v4.find(interface);
    if (si == dyn_leases_v4.end()) {
        auto x = dyn_leases_v4.emplace(std::make_pair(std::move(interface), dynlease_map_v4()));
        si = x.first;
    }
    boost::system::error_code ec;
    auto v4a = baia4::from_string(v4_addr, ec);
    if (ec) {
        fmt::print(stderr, "Bad IPv4 address at line {}: {}\n", linenum, v4_addr);
        return false;
    }
    si->second.emplace_back(std::move(v4a), macaddr, expire_time);
    if (!do_sort) return true;
    std::sort(si->second.begin(), si->second.end(),
              [](const lease_state_v4 &a, const lease_state_v4 &b) -> bool {
                    return a.addr < b.addr;
              });
    return true;
}

bool emplace_dynlease_state(size_t linenum, std::string &&interface,
                            const std::string &v6_addr, std::string &&duid,
                            uint32_t iaid, int64_t expire_time, bool do_sort)
{
    auto si = dyn_leases_v6.find(interface);
    if (si == dyn_leases_v6.end()) {
        auto x = dyn_leases_v6.emplace(std::make_pair(std::move(interface), dynlease_map_v6()));
        si = x.first;
    }
    boost::system::error_code ec;
    auto v6a = baia6::from_string(v6_addr, ec);
    if (ec) {
        fmt::print(stderr, "Bad IPv6 address at line {}: {}\n", linenum, v6_addr);
        return false;
    }
    si->second.emplace_back(std::move(v6a), std::move(duid), iaid, expire_time);
    if (!do_sort) return true;
    std::sort(si->second.begin(), si->second.end(),
              [](const lease_state_v6 &a, const lease_state_v6 &b) -> bool {
                    return a.addr < b.addr;
              });
    return true;
}

// v4 <interface> <ip> <macaddr> <expire_time>
// v6 <interface> <ip> <duid> <iaid> <expire_time>

bool dynlease_serialize(const std::string &path)
{
    const auto f = fopen(path.c_str(), "w");
    if (!f) {
        fmt::print(stderr, "failed to open '{}' for dynamic lease serialization\n");
        return false;
    }
    SCOPE_EXIT{ fclose(f); };
    std::string wbuf;
    for (const auto &i: dyn_leases_v4) {
        const auto &iface = i.first;
        const auto &ls = i.second;
        for (const auto &j: ls) {
            // Don't write out dynamic leases that have expired.
            struct timespec ts;
            if (clock_gettime(CLOCK_MONOTONIC, &ts))
                throw std::runtime_error("clock_gettime failed");
            if (ts.tv_sec >= j.expire_time)
                continue;

            wbuf = fmt::format("v4 {} {} {:02x}{:02x}{:02x}{:02x}{:02x}{:02x} {}\n",
                               iface, j.addr, j.macaddr[0], j.macaddr[1], j.macaddr[2],
                                              j.macaddr[3], j.macaddr[4], j.macaddr[5],
                               j.expire_time);
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
            if (ts.tv_sec >= j.expire_time)
                continue;

            wbuf = fmt::format("v6 {} {} ", iface, j.addr);
            for (const auto &k: j.duid)
                wbuf.append(fmt::format("{:02x}", k));
            wbuf.append(" {} {}\n", j.iaid, j.expire_time);
            const auto fs = fwrite(wbuf.c_str(), wbuf.size(), 1, f);
            if (fs != wbuf.size()) {
                fmt::print(stderr, "{}: short write {} < {}\n", __func__, fs, wbuf.size());
                return false;
            }
        }
    }
    fflush(f);
    const auto fd = fileno(f);
    fdatasync(fd);
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
        emplace_dynlease_state(linenum, std::move(cps.interface), cps.v4_addr,
                               std::move(cps.macaddr), cps.expire_time, false);
    }
    action V6EntryEn {
        emplace_dynlease_state(linenum, std::move(cps.interface), cps.v6_addr,
                               std::move(cps.duid), cps.iaid, cps.expire_time, false);
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

