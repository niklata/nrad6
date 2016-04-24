/* cfg.rl - configure file parser for nrad6
 *
 * (c) 2016 Nicholas J. Kain <njkain at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <string>
#include <cstdio>
#include <nk/scopeguard.hpp>
#include <nk/format.hpp>
#include <nk/str_to_int.hpp>
#include "dhcp_state.hpp"

#define MAX_LINE 2048

std::vector<boost::asio::ip::address_v6> dns6_servers;
std::vector<boost::asio::ip::address_v4> dns4_servers;
std::vector<std::string> dns_search;
extern void create_dns_search_blob();

/*

Our configuration file looks like:

dns_server <value>
dns_search <value>
default_lifetime <value>

// Comment
v6 <DUID> <IAID> <address> [lifetime=value]
v6 <DUID> <IAID> <address> [lifetime=value]
v6 <DUID> <IAID> <address> [lifetime=value]
v6 <DUID> <IAID> <address> [lifetime=value]

v4 <MAC> <address> [lifetime=value]

*/

struct cfg_parse_state {
    cfg_parse_state() : st(nullptr), cs(0), default_lifetime("7200") {}
    void newline() {
        duid.clear();
        iaid.clear();
        macaddr.clear();
        v4_addr.clear();
        v6_addr.clear();
    }
    const char *st;
    int cs;

    std::string duid;
    std::string iaid;
    std::string macaddr;
    std::string v4_addr;
    std::string v6_addr;
    std::string default_lifetime;
};

using baia6 = boost::asio::ip::address_v6;

%%{
    machine cfg_line_m;
    access cps.;

    action St { cps.st = p; }

    # XXX: Normalize to lowercase!
    action DuidEn { cps.duid = std::string(cps.st, p - cps.st); }
    action IaidEn { cps.iaid = std::string(cps.st, p - cps.st); }
    action V4AddrEn { cps.v4_addr = std::string(cps.st, p - cps.st); }
    action V6AddrEn { cps.v6_addr = std::string(cps.st, p - cps.st); }
    action DnsServerEn {
        boost::system::error_code ec;
        if (cps.v4_addr.size()) {
            auto v4a = boost::asio::ip::address_v4::from_string(cps.v4_addr, ec);
            if (!ec)
                dns4_servers.emplace_back(std::move(v4a));
            else
                fmt::print(stderr, "Bad IP address at line {}: {}", linenum, cps.v4_addr);
        } else {
            auto v6a = boost::asio::ip::address_v6::from_string(cps.v6_addr, ec);
            if (!ec)
                dns6_servers.emplace_back(std::move(v6a));
            else
                fmt::print(stderr, "Bad IPv6 address at line {}: {}", linenum, cps.v6_addr);
        }
    }
    action DnsSearchEn { dns_search.emplace_back(std::string(cps.st, p - cps.st)); }
    action DefLifeEn { cps.default_lifetime = std::string(cps.st, p - cps.st); }
    action MacAddrEn { cps.macaddr = std::string(cps.st, p - cps.st); }
    action V4EntryEn {
        auto r = emplace_dhcp_state(std::move(cps.macaddr), cps.v4_addr,
                                    nk::str_to_u32(cps.default_lifetime));
        if (!r)
            fmt::print(stderr, "Bad IPv4 address at line {}: {}", linenum, cps.v4_addr);
    }
    action V6EntryEn {
        auto r = emplace_dhcp_state(std::move(cps.duid), nk::str_to_u32(cps.iaid),
                                    cps.v6_addr, nk::str_to_u32(cps.default_lifetime));
        if (!r)
            fmt::print(stderr, "Bad IPv6 address at line {}: {}", linenum, cps.v6_addr);
    }

    duid = (xdigit+ | (xdigit{2} ('-' xdigit{2})*)+) >St %DuidEn;
    iaid = digit+ >St %IaidEn;
    macaddr = ((xdigit{2} ':'){5} xdigit{2}) >St %MacAddrEn;
    v4_addr = (digit{1,3} | '.')+ >St %V4AddrEn;
    v6_addr = (xdigit{1,4} | ':')+ >St %V6AddrEn;

    comment = space* ('//' any*)?;
    dns_server = space* 'dns_server' space+ (v4_addr | v6_addr) %DnsServerEn comment;
    dns_search = space* 'dns_search' space+ graph+ >St %DnsSearchEn comment;
    default_lifetime = space* 'default_lifetime' space+ digit+ >St %DefLifeEn comment;
    v4_entry = space* 'v4' space+ macaddr space+ v4_addr comment;
    v6_entry = space* 'v6' space+ duid space+ iaid space+ v6_addr comment;

    main := comment | dns_server | dns_search | default_lifetime
          | v6_entry %V6EntryEn | v4_entry %V4EntryEn;
}%%

%% write data;

static int do_parse_cfg_line(cfg_parse_state &cps, const char *p, size_t plen,
                             const size_t linenum)
{
    const char *pe = p + plen;
    const char *eof = pe;

    %% write init;
    %% write exec;

    if (cps.cs >= cfg_line_m_first_final)
        return 1;
    if (cps.cs == cfg_line_m_error)
        return -1;
    return -2;
}

void parse_config(const std::string &path)
{
    char buf[MAX_LINE];
    auto f = fopen(path.c_str(), "r");
    if (!f) {
        fmt::print(stderr, "{}: failed to open config file \"{}\" for read: {}\n",
                   __func__, path, strerror(errno));
        return;
    }
    SCOPE_EXIT{ fclose(f); };
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
        auto r = do_parse_cfg_line(ps, buf, llen, linenum);
        if (r < 0) {
            if (r == -2)
                fmt::print(stderr, "{}: Incomplete configuration at line {}; ignoring\n",
                           __func__, linenum);
            else
                fmt::print(stderr, "{}: Malformed configuration at line {}; ignoring.\n",
                           __func__, linenum);
            continue;
        }
    }
    if (!dns_search.empty())
        create_dns_search_blob();
}

