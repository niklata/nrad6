#include <iterator>
#include <nk/format.hpp>
#include "multicast6.hpp"
#include "netbits.hpp"
#include "dhcp6.hpp"
#include "attach_bpf.h"

namespace ba = boost::asio;

static auto mc6_alldhcp_ras = ba::ip::address_v6::from_string("ff02::1:2");

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

D6Listener::D6Listener(ba::io_service &io_service,
                       const std::string &ifname,
                       const char macaddr[6])
  : socket_(io_service), ifname_(ifname), using_bpf_(false)
{
    memcpy(macaddr_, macaddr, sizeof macaddr_);
    socket_.open(ba::ip::udp::v6());
    auto lla_ep = ba::ip::udp::endpoint(ba::ip::address_v6::any(), 547);
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

std::vector<uint8_t> dns_search_blob;
std::vector<uint8_t> ntp6_fqdns_blob;

// Performs DNS label wire encoding cf RFC1035 3.1
// Allocates memory frequently in order to make correctness easier to
// verify, but at least in this program, it will called only at
// reconfiguration.
static std::vector<uint8_t> dns_label(const std::string &ds)
{
    std::vector<uint8_t> ret;
    std::vector<std::pair<size_t, size_t>> locs;

    if (ds.size() <= 0)
        return ret;

    // First we build up a list of label start/end offsets.
    size_t s=0, idx=0;
    bool in_label(false);
    for (const auto &i: ds) {
        if (i == '.') {
            if (in_label) {
                locs.emplace_back(std::make_pair(s, idx));
                in_label = false;
            } else {
                throw std::runtime_error("malformed input");
            }
        } else {
            if (!in_label) {
                s = idx;
                in_label = true;
            }
        }
        ++idx;
    }
    // We don't demand a trailing dot.
    if (in_label) {
        locs.emplace_back(std::make_pair(s, idx));
        in_label = false;
    }

    // Now we just need to attach the label length octet followed
    // by the label contents.
    for (const auto &i: locs) {
        auto len = i.second - i.first;
        if (len > 63)
            throw std::runtime_error("label too long");
        ret.push_back(len);
        for (size_t j = i.first; j < i.second; ++j)
            ret.push_back(ds[j]);
    }
    // Terminating zero length label.
    if (ret.size())
        ret.push_back(0);
    if (ret.size() > 255)
        throw std::runtime_error("domain name too long");
    return ret;
}

void create_dns_search_blob()
{
    dns_search_blob.clear();
    for (const auto &dnsname: dns_search) {
        std::vector<uint8_t> lbl;
        try {
            lbl = dns_label(dnsname);
        } catch (const std::runtime_error &e) {
            fmt::print(stderr, "labelizing {} failed: {}\n", dnsname, e.what());
            continue;
        }
        dns_search_blob.insert(dns_search_blob.end(),
                               std::make_move_iterator(lbl.begin()),
                               std::make_move_iterator(lbl.end()));
    }
    // See if the search blob size is too large to encode in a RA
    // dns search option.
    if (dns_search_blob.size() > 8 * 254)
        throw std::runtime_error("dns search list is too long");
}

// Different from the dns search blob because we pre-include the
// suboption headers.
void create_ntp6_fqdns_blob()
{
    ntp6_fqdns_blob.clear();
    for (const auto &ntpname: ntp6_fqdns) {
        std::vector<uint8_t> lbl;
        try {
            lbl = dns_label(ntpname);
        } catch (const std::runtime_error &e) {
            fmt::print(stderr, "labelizing {} failed: {}\n", ntpname, e.what());
            continue;
        }
        ntp6_fqdns_blob.push_back(0);
        ntp6_fqdns_blob.push_back(3);
        uint16_t lblsize = lbl.size();
        ntp6_fqdns_blob.push_back(lblsize >> 8);
        ntp6_fqdns_blob.push_back(lblsize & 0xff);
        ntp6_fqdns_blob.insert(ntp6_fqdns_blob.end(),
                               std::make_move_iterator(lbl.begin()),
                               std::make_move_iterator(lbl.end()));
    }
}

void D6Listener::start_receive()
{
    recv_buffer_.consume(recv_buffer_.size());
    socket_.async_receive_from
        (recv_buffer_.prepare(8192), remote_endpoint_,
         [this](const boost::system::error_code &error,
                std::size_t bytes_xferred)
         {
             fmt::print(stderr, "bytes_xferred={}\n", bytes_xferred);
             recv_buffer_.commit(bytes_xferred);

             std::size_t bytes_left = bytes_xferred;
             if (!using_bpf_) {
                 // Discard if the DHCP6 length < the size of a DHCP6 header.
                 if (bytes_xferred < dhcp6_header::size) {
                    fmt::print(stderr, "DHCP6 from {} is too short: {}\n", remote_endpoint_, bytes_xferred);
                    start_receive();
                    return;
                 }
             }

             std::istream is(&recv_buffer_);
             dhcp6_header dhcp6_hdr;
             is >> dhcp6_hdr;
             bytes_left -= dhcp6_header::size;

             fmt::print(stderr, "dhcp message type: {}\n", static_cast<uint8_t>(dhcp6_hdr.msg_type()));

             if (!using_bpf_) {
                 if (dhcp6_hdr.msg_type() != dhcp6_msgtype::information_request) {
                     fmt::print(stderr, "DHCP6 Message type not InfoReq\n");
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
                 //fmt::print(stderr, "bytes_left={}\n", bytes_left);
                 dhcp6_opt opt;
                 is >> opt;
                 //fmt::print(stderr, "opt type={} length={}\n", opt.type(), opt.length());
                 bytes_left -= dhcp6_opt::size;
                 auto l = opt.length();
                 auto ot = opt.type();

                 if (l > bytes_left) {
                     fmt::print(stderr, "Option is too long.\n");
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
                 } else if (ot == 6) { // OptionRequest
                     if (l % 2) {
                         fmt::print(stderr, "Client-sent option Request has a bad length.  Ignoring.\n");
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
                         fmt::print(stderr, "Client-sent option ElapsedTime has a bad length.  Ignoring.\n");
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
             send_d6hdr.msg_type(dhcp6_msgtype::reply);
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

             if ((!optreq_exists || optreq_dns_search)
                 && dns_search_blob.size()) {
                 dhcp6_opt send_dns_search;
                 send_dns_search.type(24);
                 send_dns_search.length(dns_search_blob.size());
                 os << send_dns_search;
                 for (const auto &i: dns_search_blob)
                     os << i;
             }
             auto n6s_size = ntp6_servers.size();
             auto n6m_size = ntp6_multicasts.size();
             auto n6d_size = ntp6_fqdns_blob.size();
             if ((!optreq_exists || optreq_ntp)
                 && (n6s_size || n6m_size || n6d_size)) {
                 uint16_t len(0);
                 dhcp6_opt send_ntp;
                 send_ntp.type(56);
                 if (n6s_size)
                     len += 4 + n6s_size * 16;
                 if (n6m_size)
                     len += 4 + n6m_size * 16;
                 if (n6d_size)
                     len += n6d_size;
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
                 for (const auto &i: ntp6_fqdns_blob)
                     os << i;
             }

             boost::system::error_code ec;
             socket_.send_to(send_buffer.data(), remote_endpoint_, 0, ec);

             start_receive();
         });
}

