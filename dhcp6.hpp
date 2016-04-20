#ifndef NK_NRAD6_DHCP6_HPP_
#define NK_NRAD6_DHCP6_HPP_

#include <string>
#include <stdint.h>
#include <iterator>
#include <boost/asio.hpp>
#include "netbits.hpp"

class D6Listener
{
public:
    D6Listener(boost::asio::io_service &io_service,
               const std::string &ifname,
               const char macaddr[6]);
private:
    enum class dhcp6_msgtype {
        unknown = 0,
        solicit = 1,
        advertise = 2,
        request = 3,
        confirm = 4,
        renew = 5,
        rebind = 6,
        reply = 7,
        release = 8,
        decline = 9,
        reconfigure = 10,
        information_request = 11,
        relay_forward = 12,
        relay_reply = 13,
    };

    class dhcp6_header
    {
    public:
        dhcp6_header() { std::fill(data_, data_ + sizeof data_, 0); }
        uint32_t xid() const { return data_[1] << 16 | data_[2] << 8 | data_[3]; }
        void xid(uint32_t v) {
            data_[1] = v >> 16 & 0xff;
            data_[2] = v >> 8 & 0xff;
            data_[3] = v & 0xff;
        }
        dhcp6_msgtype msg_type() const {
            const auto dt = data_[0];
            if (dt >= 1 && dt <= 13)
                return static_cast<dhcp6_msgtype>(dt);
            return dhcp6_msgtype::unknown;
        };
        void msg_type(dhcp6_msgtype v) { data_[0] = static_cast<uint8_t>(v); }
        static const std::size_t size = 4;
        friend std::istream& operator>>(std::istream &is, dhcp6_header &header)
        {
            is.read(reinterpret_cast<char *>(header.data_), size);
            return is;
        }
        friend std::ostream& operator<<(std::ostream &os,
                                        const dhcp6_header &header)
        {
            return os.write(reinterpret_cast<const char *>(header.data_), size);
        }
    private:
        uint8_t data_[4];
    };

    class dhcp6_opt
    {
    public:
        dhcp6_opt() { std::fill(data_, data_ + sizeof data_, 0); }
        uint16_t type() const { return decode16be(data_); }
        uint16_t length() const { return decode16be(data_ + 2); }
        void type(uint16_t v) { encode16be(v, data_); }
        void length(uint16_t v) { encode16be(v, data_ + 2); }
        static const std::size_t size = 4;
        friend std::istream& operator>>(std::istream &is, dhcp6_opt &header)
        {
            is.read(reinterpret_cast<char *>(header.data_), size);
            return is;
        }
        friend std::ostream& operator<<(std::ostream &os,
                                        const dhcp6_opt &header)
        {
            return os.write(reinterpret_cast<const char *>(header.data_), size);
        }
    private:
        uint8_t data_[4];
    };

    class dhcp6_hwaddr_duid
    {
    public:
        dhcp6_hwaddr_duid() {
            std::fill(data_, data_ + sizeof data_, 0);
            // Ethernet is assumed.
            data_[1] = 3;
            data_[3] = 1;
        }
        void macaddr(const char v[6]) { memcpy(data_ + 4, v, 6); }
        static const std::size_t size = 10;
        friend std::istream& operator>>(std::istream &is, dhcp6_hwaddr_duid &header)
        {
            is.read(reinterpret_cast<char *>(header.data_), size);
            return is;
        }
        friend std::ostream& operator<<(std::ostream &os,
                                        const dhcp6_hwaddr_duid &header)
        {
            return os.write(reinterpret_cast<const char *>(header.data_), size);
        }
    private:
        uint8_t data_[10];
    };
    struct d6msg_state
    {
        d6msg_state() : optreq_exists(false), optreq_dns(false), optreq_dns_search(false),
                        optreq_info_refresh_time(false), optreq_ntp(false) {}
        dhcp6_header header;
        std::vector<uint8_t> client_duid;
        uint16_t elapsed_time;

        bool optreq_exists:1;
        bool optreq_dns:1;
        bool optreq_dns_search:1;
        bool optreq_info_refresh_time:1;
        bool optreq_ntp:1;
    };

    void write_response_header(const d6msg_state &d6s, std::ostream &os, dhcp6_msgtype mtype);
    void handle_advertise_request(const d6msg_state &d6s, boost::asio::streambuf &send_buffer);
    void handle_information_request(const d6msg_state &d6s, boost::asio::streambuf &send_buffer);
    void start_receive();
    void attach_bpf(int fd);
    boost::asio::ip::udp::socket socket_;
    boost::asio::ip::udp::endpoint remote_endpoint_;
    std::string ifname_;
    bool using_bpf_:1;
    char macaddr_[6];
    boost::asio::streambuf recv_buffer_;
};

#endif

