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

/*

Our configuration file looks like:

default_lifetime <value>

// Comment
v6 <DUID> <IAID> <address> [lifetime=value]
v6 <DUID> <IAID> <address> [lifetime=value]
v6 <DUID> <IAID> <address> [lifetime=value]
v6 <DUID> <IAID> <address> [lifetime=value]

*/

struct cfg_parse_state {
    cfg_parse_state() : st(nullptr), cs(0), default_lifetime("7200") {}
    const char *st;
    int cs;

    std::string duid;
    std::string iaid;
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
    action V6AddrEn { cps.v6_addr = std::string(cps.st, p - cps.st); }
    action DefLifeEn { cps.default_lifetime = std::string(cps.st, p - cps.st); }
    # XXX: Catch exception from baia6::from_string()!
    action V6EntryEn {
        emplace_dhcp_state(std::move(cps.duid), nk::str_to_u32(cps.iaid),
                           cps.v6_addr, nk::str_to_u32(cps.default_lifetime));
     }

    duid = (xdigit+ | (xdigit{2} ('-' xdigit{2})*)+) >St %DuidEn;
    iaid = digit+ >St %IaidEn;
    v6_addr = (xdigit{1,4} | ':')+ >St %V6AddrEn;

    comment = space* ('//' any*)?;
    default_lifetime = space* 'default_lifetime' space+ digit+ >St %DefLifeEn space*;
    v6_entry = space* 'v6' space+ duid space+ iaid space+ v6_addr space*;

    main := comment | default_lifetime | v6_entry %V6EntryEn;
}%%

%% write data;

static int do_parse_cfg_line(cfg_parse_state &cps, const char *p, size_t plen)
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
        cfg_parse_state ps;
        auto r = do_parse_cfg_line(ps, buf, llen);
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
}

