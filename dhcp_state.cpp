#include <unordered_map>
#include <nk/format.hpp>
#include <boost/asio.hpp>
#include "dhcp_state.hpp"

using baia6 = boost::asio::ip::address_v6;
using baia4 = boost::asio::ip::address_v4;

static std::unordered_multimap<std::string, std::unique_ptr<iaid_mapping>> duid_mapping;
static std::unordered_map<std::string, std::unique_ptr<dhcpv4_entry>> macaddr_mapping;

bool emplace_dhcp_state(std::string &&duid, uint32_t iaid, const std::string &v6_addr,
                        uint32_t default_lifetime)
{
    boost::system::error_code ec;
    auto v6a = baia6::from_string(v6_addr, ec);
    if (ec) return false;
    fmt::print("STATEv6: {} {} {} {}\n", duid, iaid, v6_addr, default_lifetime);
    duid_mapping.emplace
        (std::make_pair(std::move(duid),
                        std::make_unique<iaid_mapping>(iaid, v6a, default_lifetime)));
    return true;
}

bool emplace_dhcp_state(std::string &&macaddr, const std::string &v4_addr,
                        uint32_t default_lifetime)
{
    boost::system::error_code ec;
    auto v4a = baia4::from_string(v4_addr, ec);
    if (ec) return false;
    fmt::print("STATEv4: {} {} {}\n", macaddr, v4_addr, default_lifetime);
    macaddr_mapping.emplace
        (std::make_pair(std::move(macaddr),
                        std::make_unique<dhcpv4_entry>(v4a, default_lifetime)));
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
