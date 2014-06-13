#ifndef NK_NRAD6_DHCP6_HPP_
#define NK_NRAD6_DHCP6_HPP_

#include <string>
#include <stdint.h>
#include <boost/asio.hpp>

class D6Listener
{
public:
    D6Listener(boost::asio::io_service &io_service,
               boost::asio::ip::address_v6 &lla,
               const std::string &ifname,
               const char macaddr[6]);
private:
    void start_receive();
    boost::asio::ip::udp::socket socket_;
    boost::asio::ip::address_v6 lla_;
    boost::asio::ip::udp::endpoint remote_endpoint_;
    std::string ifname_;
    char macaddr_[6];
    boost::asio::streambuf recv_buffer_;
};

#endif

