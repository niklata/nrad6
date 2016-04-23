#ifndef NK_NRAD6_DHCP_STATE_HPP_
#define NK_NRAD6_DHCP_STATE_HPP_

#include <boost/asio.hpp>

struct iaid_mapping {
    iaid_mapping(uint32_t iaid_, const boost::asio::ip::address_v6 &addr_, uint32_t lifetime_)
        : address(addr_), iaid(iaid_), lifetime(lifetime_) {}
    boost::asio::ip::address_v6 address;
    uint32_t iaid;
    uint32_t lifetime;
};

void init_dhcp_state();
bool emplace_dhcp_state(std::string &&duid, uint32_t iaid, const std::string &v6_addr,
                        uint32_t default_lifetime);
const iaid_mapping* query_dhcp_state(const std::string &duid, uint32_t iaid);

#endif

