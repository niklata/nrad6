#include <unordered_map>
#include "dhcp_state.hpp"
#include <nk/format.hpp>
#include <boost/asio.hpp>

extern void parse_config(const std::string &path);

using baia6 = boost::asio::ip::address_v6;

static std::unordered_multimap<std::string, std::unique_ptr<iaid_mapping>> duid_mapping;

void init_dhcp_state()
{
    parse_config("/etc/nrad6.conf");
}

bool emplace_dhcp_state(std::string &&duid, uint32_t iaid, const std::string &v6_addr,
                        uint32_t default_lifetime)
{
    boost::system::error_code ec;
    auto v6a = baia6::from_string(v6_addr, ec);
    if (ec) return false;
    fmt::print("STATE: {} {} {} {}\n", duid, iaid, v6_addr, default_lifetime);
    duid_mapping.emplace
        (std::make_pair(std::move(duid),
                        std::make_unique<iaid_mapping>(iaid, v6a, default_lifetime)));
    return true;
}

const iaid_mapping *query_dhcp_state(const std::string &duid, uint32_t iaid)
{
    auto f = duid_mapping.equal_range(duid);
    for (auto i = f.first; i != f.second; ++i) {
        if (i->second->iaid == iaid)
            return i->second.get();
    }
    return nullptr;
}

