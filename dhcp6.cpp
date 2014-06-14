#include "multicast6.hpp"
#include "netbits.hpp"
#include "dhcp6.hpp"
#include "attach_bpf.h"

namespace ba = boost::asio;

static auto mc6_alldhcp_ras = ba::ip::address_v6::from_string("ff02::1:2");

class dhcp6_header
{
public:
    dhcp6_header() { std::fill(data_, data_ + sizeof data_, 0); }
    uint8_t msg_type() const { return data_[0]; }
    uint32_t xid() const { return data_[1] << 16 | data_[2] << 8 | data_[3]; }
    void msg_type(uint8_t v) { data_[0] = v; }
    void xid(uint32_t v) {
        data_[1] = v >> 16 & 0xff;
        data_[2] = v >> 8 & 0xff;
        data_[3] = v & 0xff;
    }
    bool is_information_request() const { return data_[0] == 11; }
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

D6Listener::D6Listener(ba::io_service &io_service,
                       ba::ip::address_v6 &lla,
                       const std::string &ifname,
                       const char macaddr[6])
  : socket_(io_service), lla_(lla), ifname_(ifname), using_bpf_(false)
{
    memcpy(macaddr_, macaddr, sizeof macaddr_);
    socket_.open(ba::ip::udp::v6());
    auto lla_ep = ba::ip::udp::endpoint(lla_, 547);
    attach_multicast(socket_.native(), ifname, mc6_alldhcp_ras);
    attach_bpf(socket_.native());
    socket_.bind(lla_ep);

    start_receive();
}

void D6Listener::attach_bpf(int fd)
{
    using_bpf_ = attach_bpf_dhcp6_info(fd, ifname_.c_str());
}

std::vector<boost::asio::ip::address_v6> dns6_servers;
std::vector<boost::asio::ip::address_v6> ntp6_servers;
std::vector<boost::asio::ip::address_v6> ntp6_multicasts;
std::vector<std::string> ntp6_fqdns;
std::vector<std::string> dns_search;

void D6Listener::start_receive()
{
    recv_buffer_.consume(recv_buffer_.size());
    socket_.async_receive_from
        (recv_buffer_.prepare(8192), remote_endpoint_,
         [this](const boost::system::error_code &error,
                std::size_t bytes_xferred)
         {
             //std::cerr << "bytes_xferred=" << bytes_xferred << std::endl;
             recv_buffer_.commit(bytes_xferred);

             std::size_t bytes_left = bytes_xferred;
             if (!using_bpf_) {
                 // Discard if the DHCP6 length < the size of a DHCP6 header.
                 if (bytes_xferred < dhcp6_header::size) {
                    std::cerr << "DHCP6 from " << remote_endpoint_ << " is too short: " << bytes_xferred << std::endl;
                    start_receive();
                    return;
                 }
             }

             std::istream is(&recv_buffer_);
             dhcp6_header dhcp6_hdr;
             is >> dhcp6_hdr;
             bytes_left -= dhcp6_header::size;

             if (!using_bpf_) {
                 if (!dhcp6_hdr.is_information_request()) {
                     std::cerr << "DHCP6 Message type not InfoReq" << std::endl;
                     start_receive();
                     return;
                 }
             }

             std::vector<uint8_t> client_duid;
             uint16_t elapsed_time;

             bool optreq_exists(false);
             bool optreq_dns(false);
             bool optreq_dns_search(false);
             bool optreq_info_refresh_time(false);
             bool optreq_ntp(false);

             while (bytes_left >= 4) {
                 //std::cerr << "bytes_left=" << bytes_left << std::endl;
                 dhcp6_opt opt;
                 is >> opt;
                 //std::cerr << "opt type=" << opt.type() << " length="
                 //          << opt.length() << std::endl;
                 bytes_left -= dhcp6_opt::size;
                 auto l = opt.length();
                 auto ot = opt.type();

                 if (l > bytes_left) {
                     std::cerr << "Option is too long." << std::endl;
                     while (bytes_left--)
                         is.get();
                     continue;
                 }

                 if (ot == 1) { // ClientID
                     client_duid.reserve(l);
                     while (l--) {
                         client_duid.push_back(is.get());
                         --bytes_left;
                     }
                     std::cerr << std::endl;
                 } else if (ot == 6) { // OptionRequest
                     if (l % 2) {
                         std::cerr << "Client-sent option Request has a bad length.  Ignoring." << std::endl;
                         while (l--) {
                             is.get();
                             --bytes_left;
                         }
                         continue;
                     }
                     optreq_exists = true;
                     l /= 2;
                     while (l--) {
                         char b[2];
                         b[1] = is.get();
                         b[0] = is.get();
                         bytes_left -= 2;
                         uint16_t v;
                         memcpy(&v, b, 2);
                         switch (v) {
                         case 23: optreq_dns = true; break;
                         case 24: optreq_dns_search = true; break;
                         case 32: optreq_info_refresh_time = true; break;
                         case 56: optreq_ntp = true; break;
                         default: break;
                         }
                     }
                 } else if (ot == 8) { // ElapsedTime
                     // 16-bit hundreths of a second since start of exchange
                     if (l != 2) {
                         std::cerr << "Client-sent option ElapsedTime has a bad length.  Ignoring." << std::endl;
                         while (l--) {
                             is.get();
                             --bytes_left;
                         }
                         continue;
                     }
                     char b[2];
                     b[1] = is.get();
                     b[0] = is.get();
                     bytes_left -= 2;
                     memcpy(&elapsed_time, b, 2);
                 } else {
                     while (l--) {
                         is.get();
                         --bytes_left;
                     }
                 }
             }

             dhcp6_header send_d6hdr;
             send_d6hdr.msg_type(7); // REPLY
             send_d6hdr.xid(dhcp6_hdr.xid());

             ba::streambuf send_buffer;
             std::ostream os(&send_buffer);
             os << send_d6hdr;

             dhcp6_opt send_serverid;
             send_serverid.type(2);
             send_serverid.length(10);
             os << send_serverid;
             dhcp6_hwaddr_duid send_hwduid;
             send_hwduid.macaddr(macaddr_);
             os << send_hwduid;

             if (client_duid.size()) {
                 dhcp6_opt send_clientid;
                 send_clientid.type(1);
                 send_clientid.length(client_duid.size());
                 os << send_clientid;
                 for (const auto &i: client_duid)
                     os << i;
             }

             // If opt_req.size() == 0 then send DnsServers, DomainList,
             // and NtpServer.  Otherwise, for each of these types,
             // see if it is in the opt_req before adding it to the reply.

             if ((!optreq_exists || optreq_dns) && dns6_servers.size()) {
                 dhcp6_opt send_dns;
                 send_dns.type(23);
                 send_dns.length(dns6_servers.size() * 16);
                 os << send_dns;
                 for (const auto &i: dns6_servers) {
                     auto d6b = i.to_bytes();
                     for (const auto &j: d6b)
                         os << j;
                 }
             }

             if ((!optreq_exists || optreq_dns_search) && dns_search.size()) {
                 dhcp6_opt send_dns_search;
                 send_dns_search.type(24);
                 // XXX: Break into labels.
             }
             auto n6s_size = ntp6_servers.size();
             auto n6m_size = ntp6_multicasts.size();
             auto n6d_size = ntp6_fqdns.size();
             if ((!optreq_exists || optreq_ntp)
                 && (n6s_size || n6m_size || n6d_size)) {
                 uint16_t len(0);
                 dhcp6_opt send_ntp;
                 send_ntp.type(56);
                 if (n6s_size)
                     len += 4 + n6s_size * 16;
                 if (n6m_size)
                     len += 4 + n6m_size * 16;
                 if (n6d_size) {
                     len += 4;
                     // XXX: Break into labels.
                 }
                 send_ntp.length(len);
                 os << send_ntp;

                 for (const auto &i: ntp6_servers) {
                     uint16_t soc(1);
                     uint16_t sol(16);
                     os << soc << sol;
                     auto n6b = i.to_bytes();
                     for (const auto &j: n6b)
                         os << j;
                 }
                 for (const auto &i: ntp6_multicasts) {
                     uint16_t soc(2);
                     uint16_t sol(16);
                     os << soc << sol;
                     auto n6b = i.to_bytes();
                     for (const auto &j: n6b)
                         os << j;
                 }
                 //for (const auto &i: ntp6_fqdns) {
                     //uint16_t soc(3);
                    // XXX: Break into labels.
                 //}
             }

             boost::system::error_code ec;
             socket_.send_to(send_buffer.data(), remote_endpoint_, 0, ec);

             start_receive();
         });
}

