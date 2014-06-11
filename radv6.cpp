/* radv6.cpp - ipv6 router advertisement handling
 *
 * (c) 2014 Nicholas J. Kain <njkain at gmail dot com>
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

#include <sstream>
#include <algorithm>

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include <net/if.h>
#include <sys/socket.h>

#include <boost/lexical_cast.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>

#include "make_unique.hpp"
#include "radv6.hpp"
#include "nlsocket.hpp"

extern "C" {
#include "nk/log.h"
#include "nk/net_checksum.h"
}

/* XXX: Configuration options:
 *
 * is_router = false :: Can we forward packets to/from the interface?
 *                      -> If true, we send periodic router advertisements.
 * Send times are randomized between interval/min_interval using
 * a UNIFORM distribution.
 * advert_interval_sec = 600 :: Maximum time between multicast router
 *                              adverts.  min=4, max=1800
 * advert_min_interval_sec (NOT CONFIGURABLE) ::
 *                 min,max = [3, 0.75 * advert_interval_sec]
 *                 default = max(0.33 * advert_interval_sec, 3)
 *
 * is_managed = false :: Does the network use DHCPv6 for address assignment?
 * other_config = false :: Does the network use DHCPv6 for other net info?
 * mtu = 0 :: Advertise specified MTU if value >= IPv6 Min MTU (1280?)
 * reachable_time = 0 :: Value for the reachable time field.
 *                       0 means unspecified.
 *                       Must be <= 3600000ms (1h)
 * retransmit_time = 0 :: Value for the retransmit time field.
 *                       0 means unspecified.
 * curhoplimit = 0 :: Value for the Cur Hop Limit field.
 *                       0 means unspecified.
 * default_lifetime = 3 * advert_interval_sec ::
 *                Router lifetime field value.
 *
 * prefix_list = everything but link local ::
 *                Prefix Information options.
 *                Valid Lifetime should default to 2592000 seconds (30d)
 *                On Link Flag (L-bit) : True
 *                Preferred Lifetime should default to 604800 seconds (7d)
 *                    MUST be <= Valid Lifetime
 *                Autonomous Flag: True
 */

namespace ba = boost::asio;

static inline void encode32be(uint32_t v, uint8_t *dest)
{
    dest[0] = v >> 24;
    dest[1] = (v >> 16) & 0xff;
    dest[2] = (v >> 8) & 0xff;
    dest[3] = v & 0xff;
}

static inline void encode16be(uint16_t v, uint8_t *dest)
{
    dest[0] = v >> 8;
    dest[1] = v & 0xff;
}

static inline uint32_t decode32be(const uint8_t *src)
{
    return (static_cast<uint32_t>(src[0]) << 24)
         | ((static_cast<uint32_t>(src[1]) << 16) & 0xff0000)
         | ((static_cast<uint32_t>(src[2]) << 8) & 0xff00)
         | (static_cast<uint32_t>(src[3]) & 0xff);
}

static inline uint16_t decode16be(const uint8_t *src)
{
    return (static_cast<uint16_t>(src[0]) << 8)
         | (static_cast<uint16_t>(src[1]) & 0xff);
}

static inline void toggle_bit(bool v, uint8_t *data,
                              std::size_t arrayidx, uint32_t bitidx)
{
    if (v)
        data[arrayidx] |= bitidx;
    else
        data[arrayidx] &= ~bitidx;
}

class ipv6_header
{
public:
    ipv6_header() { std::fill(data_, data_ + sizeof data_, 0); }
    uint8_t version() const { return (data_[0] >> 4) & 0xf; }
    uint8_t traffic_class() const {
        return (static_cast<uint32_t>(data_[0] & 0xf) << 4)
             | (static_cast<uint32_t>(data_[1] >> 4) & 0xf);
    }
    uint32_t flow_label() const {
        return (static_cast<uint32_t>(data_[1] & 0xf) << 16)
             | ((static_cast<uint32_t>(data_[2]) << 8) | data_[3]);
    }
    uint16_t payload_length() const {
        return decode16be(data_ + 4);
    }
    uint8_t next_header() const {
        return data_[6];
    }
    uint8_t hop_limit() const {
        return data_[7];
    }
    boost::asio::ip::address_v6 source_address() const
    {
        boost::asio::ip::address_v6::bytes_type bytes
            = { { data_[ 8], data_[ 9], data_[10], data_[11],
                  data_[12], data_[13], data_[14], data_[15],
                  data_[16], data_[17], data_[18], data_[19],
                  data_[20], data_[21], data_[22], data_[23] } };
        return boost::asio::ip::address_v6(bytes);
    }
    boost::asio::ip::address_v6 destination_address() const
    {
        boost::asio::ip::address_v6::bytes_type bytes
            = { { data_[24], data_[25], data_[26], data_[27],
                  data_[28], data_[29], data_[30], data_[31],
                  data_[32], data_[33], data_[34], data_[35],
                  data_[36], data_[37], data_[38], data_[39] } };
        return boost::asio::ip::address_v6(bytes);
    }
    static const std::size_t size = 40;
    friend std::istream& operator>>(std::istream &is, ipv6_header &header)
    {
        is.read(reinterpret_cast<char *>(header.data_), size);
        if (header.version() != 6)
            is.setstate(std::ios::failbit);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os,
                                    const ipv6_header &header)
    {
        return os.write(reinterpret_cast<const char *>(header.data_), size);
    }
private:
    uint8_t data_[40];
};

class icmp_header
{
public:
    icmp_header() { std::fill(data_, data_ + sizeof data_, 0); }
    uint8_t type() const { return data_[0]; }
    uint8_t code() const { return data_[1]; }
    uint16_t checksum() const { return decode16be(data_ + 2); }
    void type(uint8_t v) { data_[0] = v; }
    void code(uint8_t v) { data_[1] = v; }
    void checksum(uint16_t v) { encode16be(v, data_ + 2); }
    static const std::size_t size = 4;
    friend std::istream& operator>>(std::istream &is, icmp_header &header)
    {
        is.read(reinterpret_cast<char *>(header.data_), size);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os,
                                    const icmp_header &header)
    {
        return os.write(reinterpret_cast<const char *>(header.data_), size);
    }
private:
    uint8_t data_[4];
};

class ra6_solicit_header
{
public:
    ra6_solicit_header() { std::fill(data_, data_ + sizeof data_, 0); }
    // Just a reserved 32-bit field.
    // Follow with MTU and Prefix Information options.
    static const std::size_t size = 4;
    friend std::istream& operator>>(std::istream &is, ra6_solicit_header &header)
    {
        is.read(reinterpret_cast<char *>(header.data_), size);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os,
                                    const ra6_solicit_header &header)
    {
        return os.write(reinterpret_cast<const char *>(header.data_), size);
    }
private:
    uint8_t data_[4];
};

class ra6_advert_header
{
public:
    ra6_advert_header() { std::fill(data_, data_ + sizeof data_, 0); }
    uint8_t hoplimit() const { return data_[0]; }
    bool managed_addresses() const { return data_[1] & (1 << 7); }
    bool other_stateful() const { return data_[1] & (1 << 6); }
    uint16_t router_lifetime() const { return decode16be(data_ + 2); }
    uint32_t reachable_time() const { return decode32be(data_ + 4); }
    uint32_t retransmit_timer() const { return decode32be(data_ + 8); }
    void hoplimit(uint8_t v) { data_[0] = v; }
    void managed_addresses(bool v) { toggle_bit(v, data_, 1, 1 << 7); }
    void other_stateful(bool v) { toggle_bit(v, data_, 1, 1 << 6); }
    enum class RouterPref { High, Medium, Low };
    void default_router_preference(RouterPref v) {
        switch (v) {
        case RouterPref::High:
            toggle_bit(false, data_, 1, 1 << 4);
            toggle_bit(true, data_, 1, 1 << 3);
            break;
        case RouterPref::Medium:
            toggle_bit(false, data_, 1, 1 << 4);
            toggle_bit(false, data_, 1, 1 << 3);
            break;
        case RouterPref::Low:
            toggle_bit(true, data_, 1, 1 << 4);
            toggle_bit(true, data_, 1, 1 << 3);
            break;
        }
    }
    void router_lifetime(uint16_t v) { encode16be(v, data_ + 2); }
    void reachable_time(uint32_t v) { encode32be(v, data_ + 4); }
    void retransmit_timer(uint32_t v) { encode32be(v, data_ + 8); }
    // Follow with MTU and Prefix Information options.
    static const std::size_t size = 12;
    friend std::istream& operator>>(std::istream &is, ra6_advert_header &header)
    {
        is.read(reinterpret_cast<char *>(header.data_), size);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os,
                                    const ra6_advert_header &header)
    {
        return os.write(reinterpret_cast<const char *>(header.data_), size);
    }
private:
    uint8_t data_[12];
};

class ra6_source_lla_opt
{
public:
    ra6_source_lla_opt() {
        std::fill(data_, data_ + sizeof data_, 0);
        data_[0] = 1;
        data_[1] = 1;
    }
    uint8_t type() const { return data_[0]; }
    uint8_t length() const { return data_[1] * 8; }
    const uint8_t *macaddr() const { return data_ + 2; }
    void macaddr(char *mac, std::size_t maclen) {
        if (maclen != 6)
            throw std::logic_error("wrong maclen");
        memcpy(data_ + 2, mac, 6);
    }
    static const std::size_t size = 8;
    friend std::istream& operator>>(std::istream &is, ra6_source_lla_opt &opt)
    {
        is.read(reinterpret_cast<char *>(opt.data_), size);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os,
                                    const ra6_source_lla_opt &header)
    {
        return os.write(reinterpret_cast<const char *>(header.data_), size);
    }
private:
    uint8_t data_[8];
};

class ra6_mtu_opt
{
public:
    ra6_mtu_opt() {
        std::fill(data_, data_ + sizeof data_, 0);
        data_[0] = 5;
        data_[1] = 1;
    }
    uint8_t type() const { return data_[0]; }
    uint8_t length() const { return data_[1] * 8; }
    uint32_t mtu() const { return decode32be(data_ + 4); }
    void mtu(uint32_t v) { encode32be(v, data_ + 4); }
    static const std::size_t size = 8;
    friend std::istream& operator>>(std::istream &is, ra6_mtu_opt &opt)
    {
        is.read(reinterpret_cast<char *>(opt.data_), size);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os,
                                    const ra6_mtu_opt &header)
    {
        return os.write(reinterpret_cast<const char *>(header.data_), size);
    }
private:
    uint8_t data_[8];
};

class ra6_prefix_info_opt
{
public:
    ra6_prefix_info_opt() {
        std::fill(data_, data_ + sizeof data_, 0);
        data_[0] = 3;
        data_[1] = 4;
    }
    uint8_t type() const { return data_[0]; }
    uint8_t length() const { return data_[1]; }
    uint8_t prefix_length() const { return data_[2]; }
    bool on_link() const { return data_[3] & (1 << 7); }
    bool auto_addr_cfg() const { return data_[3] & (1 << 6); }
    uint32_t valid_lifetime() const { return decode32be(data_ + 4); }
    uint32_t preferred_lifetime() const { return decode32be(data_ + 8); }
    boost::asio::ip::address_v6 prefix() const
    {
        boost::asio::ip::address_v6::bytes_type bytes
            = { { data_[16], data_[17], data_[18], data_[19],
                  data_[20], data_[21], data_[22], data_[23],
                  data_[24], data_[25], data_[26], data_[27],
                  data_[28], data_[29], data_[30], data_[31] } };
        return boost::asio::ip::address_v6(bytes);
    }
    void on_link(bool v) { toggle_bit(v, data_, 3, 1 << 7); }
    void auto_addr_cfg(bool v) { toggle_bit(v, data_, 3, 1 << 6); }
    void valid_lifetime(uint32_t v) { encode32be(v, data_ + 4); }
    void preferred_lifetime(uint32_t v) { encode32be(v, data_ + 8); }
    void prefix(const boost::asio::ip::address_v6 &v, uint8_t pl) {
        uint8_t a6[16];
        data_[2] = pl;
        auto bytes = v.to_bytes();
        memcpy(a6, bytes.data(), 16);
        uint8_t keep_bytes = pl / 8;
        uint8_t keep_bits = pl % 8;
        if (keep_bits == 0)
            memset(a6 + keep_bytes, 0, 16 -  keep_bytes);
        else {
            memset(a6 + keep_bytes + 1, 0, 16 - keep_bytes - 1);
            uint8_t mask = 0xff;
            while (keep_bits--)
                mask >>= 1;
            a6[keep_bytes] &= ~mask;
        }
        memcpy(data_ + 16, a6, sizeof a6);
    }
    static const std::size_t size = 32;
    friend std::istream& operator>>(std::istream &is, ra6_prefix_info_opt &opt)
    {
        is.read(reinterpret_cast<char *>(opt.data_), size);
        return is;
    }
    friend std::ostream& operator<<(std::ostream &os,
                                    const ra6_prefix_info_opt &header)
    {
        return os.write(reinterpret_cast<const char *>(header.data_), size);
    }
private:
    uint8_t data_[32];
};

/*
 * We will need to minimally support DHCPv6 for providing
 * DNS server information.  We will support RFC6106, too, but
 * Windows needs DHCPv6 for DNS.
 */
extern std::unique_ptr<NLSocket> nl_socket;
static auto mc6_allhosts = ba::ip::address_v6::from_string("ff02::1");
static auto mc6_allrouters = ba::ip::address_v6::from_string("ff02::2");
static const uint8_t icmp_nexthdr(58); // Assigned value
extern boost::random::mt19937 g_random_prng;

// Can throw std::out_of_range
RA6Listener::RA6Listener(ba::io_service &io_service, const std::string &ifname)
    : timer_(io_service), resolver_(io_service), socket_(io_service),
      ifname_(ifname), advi_s_max_(600)
{
    int ifidx = nl_socket->get_ifindex(ifname_);
    auto &ifinfo = nl_socket->interfaces.at(ifidx);
    for (const auto &i: ifinfo.addrs_v6) {
        if (i.scope == netif_addr::Scope::Link) {
            lla_ = i.address;
            std::cout << "if<" << ifname << "> LLA: " << lla_ << "\n";
            break;
        }
    }

    const ba::ip::icmp::endpoint lla_ep(lla_, 0x20);
    socket_.open(ba::ip::icmp::v6());
    socket_.bind(lla_ep);
    int fd = socket_.native();

    struct ifreq ifr;
    memset(&ifr, 0, sizeof (struct ifreq));
    memcpy(ifr.ifr_name, ifname.c_str(), ifname.size());
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof ifr) < 0)
        suicide("failed to bind socket to device: %s", strerror(errno));
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                   &ifidx, sizeof ifidx) < 0)
        suicide("failed to set multicast interface for socket: %s", strerror(errno));
    int loopback(0);
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                   &loopback, sizeof loopback) < 0)
        suicide("failed to disable multicast loopback for socket: %s", strerror(errno));
    int hops(255);
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                   &hops, sizeof hops) < 0)
        suicide("failed to disable multicast hops for socket: %s", strerror(errno));
    auto mrb = mc6_allrouters.to_bytes();
    struct ipv6_mreq mr;
    memcpy(&mr.ipv6mr_multiaddr, mrb.data(), sizeof mrb);
    mr.ipv6mr_interface = ifidx;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
                   &mr, sizeof mr) < 0)
        suicide("failed to join router multicast group for socket: %s", strerror(errno));

#if 0
    ba::ip::multicast::join_group mc_routers_group(mc6_allrouters);
    socket_.set_option(mc_routers_group);
#endif

    send_advert(boost::optional<ba::ip::address_v6>());
    start_periodic_announce();
    start_receive();
}

void RA6Listener::set_advi_s_max(unsigned int v)
{
    v = std::max(v, 4U);
    v = std::min(v, 1800U);
    advi_s_max_ = v;
}

void RA6Listener::start_periodic_announce()
{
    unsigned int advi_s_min = std::max(advi_s_max_ / 3, 3U);
    boost::random::uniform_int_distribution<> dist(advi_s_min, advi_s_max_);
    auto advi_s = dist(g_random_prng);
    std::cerr << "advi_s = " << advi_s << std::endl;
    timer_.expires_from_now(boost::posix_time::seconds(advi_s));
    timer_.async_wait
        ([this](const boost::system::error_code &ec)
         {
             if (ec)
                return;
             std::cerr << "periodic announce" << std::endl;
             try {
                send_advert(boost::optional<ba::ip::address_v6>());
             } catch (const std::out_of_range &) {}
             start_periodic_announce();
         });
}

// Can throw std::out_of_range
void RA6Listener::send_advert(boost::optional<ba::ip::address_v6> ucaddr)
{
    icmp_header icmp_hdr;
    ra6_advert_header ra6adv_hdr;
    ra6_source_lla_opt ra6_slla;
    ra6_mtu_opt ra6_mtu;
    std::vector<ra6_prefix_info_opt> ra6_pfxs;
    uint16_t csum;
    uint32_t pktl(sizeof icmp_hdr + sizeof ra6adv_hdr + sizeof ra6_slla
                  + sizeof ra6_mtu);

    icmp_hdr.type(134);
    icmp_hdr.code(0);
    icmp_hdr.checksum(0);
    csum = net_checksum161c(&icmp_hdr, sizeof icmp_hdr);

    ra6adv_hdr.hoplimit(0);
    ra6adv_hdr.managed_addresses(false);
    ra6adv_hdr.other_stateful(false);
    ra6adv_hdr.router_lifetime(3 * advi_s_max_);
    ra6adv_hdr.reachable_time(0);
    ra6adv_hdr.retransmit_timer(0);
    csum = net_checksum161c_add
        (csum, net_checksum161c(&ra6adv_hdr, sizeof ra6adv_hdr));

    auto ifidx = nl_socket->get_ifindex(ifname_);
    auto &ifinfo = nl_socket->interfaces.at(ifidx);

    ra6_slla.macaddr(ifinfo.macaddr, sizeof ifinfo.macaddr);
    csum = net_checksum161c_add
        (csum, net_checksum161c(&ra6_slla, sizeof ra6_slla));
    ra6_mtu.mtu(ifinfo.mtu);
    csum = net_checksum161c_add
        (csum, net_checksum161c(&ra6_mtu, sizeof ra6_mtu));

    // Prefix Information
    for (const auto &i: ifinfo.addrs_v6) {
        if (i.scope == netif_addr::Scope::Global) {
            ra6_prefix_info_opt ra6_pfxi;
            ra6_pfxi.prefix(i.address, i.prefixlen);
            ra6_pfxi.on_link(true);
            ra6_pfxi.auto_addr_cfg(true);
            ra6_pfxi.valid_lifetime(2592000);
            ra6_pfxi.preferred_lifetime(604800);
            ra6_pfxs.push_back(ra6_pfxi);
            csum = net_checksum161c_add
                (csum, net_checksum161c(&ra6_pfxi, sizeof ra6_pfxi));
            pktl += sizeof ra6_pfxi;
            break;
        }
    }

    auto llab = lla_.to_bytes();
    ba::ip::address_v6::bytes_type dstb;
    dstb = ucaddr ? ucaddr->to_bytes() : mc6_allhosts.to_bytes();
    csum = net_checksum161c_add(csum, net_checksum161c(&llab, sizeof llab));
    csum = net_checksum161c_add(csum, net_checksum161c(&dstb, sizeof dstb));
    csum = net_checksum161c_add(csum, net_checksum161c(&pktl, sizeof pktl));
    csum = net_checksum161c_add(csum, net_checksum161c(&icmp_nexthdr, 1));
    icmp_hdr.checksum(csum);

    ba::streambuf send_buffer;
    std::ostream os(&send_buffer);
    os << icmp_hdr << ra6adv_hdr << ra6_slla << ra6_mtu;
    for (const auto &i: ra6_pfxs)
        os << i;

    ba::ip::icmp::endpoint dst(ucaddr ? *ucaddr : mc6_allhosts, 0);
    boost::system::error_code ec;
    socket_.send_to(send_buffer.data(), dst, 0, ec);
}

#include <iomanip>
void RA6Listener::start_receive()
{
    recv_buffer_.consume(recv_buffer_.size());
    socket_.async_receive_from
        (recv_buffer_.prepare(8192), remote_endpoint_,
         [this](const boost::system::error_code &error,
                std::size_t bytes_xferred)
         {
             recv_buffer_.commit(bytes_xferred);
             std::cerr << "ICMP (len=" << bytes_xferred << ") from " << remote_endpoint_ << std::endl;

             auto xy = ba::buffer_cast<const char *>(recv_buffer_.data());
             for (size_t i = 0; i < bytes_xferred; ++i) 
                 std::cout << " " << std::hex << std::setw(2) << static_cast<int>(static_cast<uint8_t>(xy[i]));
             std::cout << std::dec << std::endl;

             // Discard if the ICMP length < 8 octets.
             std::size_t bytes_left = bytes_xferred;
             if (bytes_xferred < icmp_header::size
                                 + ra6_solicit_header::size) {
                std::cerr << "ICMP from " << remote_endpoint_ << " is too short: " << bytes_xferred << std::endl;
                start_receive();
                return;
             }

             std::istream is(&recv_buffer_);
             icmp_header icmp_hdr;
             is >> icmp_hdr;
             bytes_left -= icmp_header::size;

             // XXX: Discard if the ip header hop limit field != 255
#if 0
             if (ipv6_hdr.hop_limit() != 255) {
                std::cerr << "Hop limit != 255" << std::endl;
                start_receive();
                return;
             }
#endif

             // Discard if the ICMP code is not 0.
             if (icmp_hdr.code() != 0) {
                std::cerr << "ICMP code != 0" << std::endl;
                start_receive();
                return;
             }

             if (icmp_hdr.type() != 133) {
                std::cerr << "ICMP type != 133" << std::endl;
                start_receive();
                return;
             }

             ra6_solicit_header ra6_solicit_hdr;
             is >> ra6_solicit_hdr;
             bytes_left -= ra6_solicit_header::size;

             uint8_t macaddr[6];
             bool got_macaddr(false);

             // Only the source link-layer address option is defined.
             while (bytes_left > 1) {
                 uint8_t opt_type, c;
                 is >> opt_type >> c;
                 std::size_t opt_length = 8 * c;
                 // Discard if any included option has a length <= 0.
                 if (opt_length <= 0) {
                     std::cerr << "Solicitation option length == 0" << std::endl;
                     start_receive();
                     return;
                 }
                 if (opt_type == 1 && opt_length == 8 && !got_macaddr) {
                     got_macaddr = true;
                     for (size_t i = 0; i < sizeof macaddr; ++i)
                         is >> macaddr[i];
                 } else {
                     if (opt_type == 1) {
                         if (opt_length != 8)
                             std::cerr << "Source Link-Layer Address is wrong size for ethernet." << std::endl;
                         else
                             std::cerr << "Solicitation has more than one Source Link-Layer Address option.  Using the first." << std::endl;
                     }
                     for (size_t i = 0; i < opt_length - 2; ++i)
                         is >> c;
                 }
                 bytes_left -= opt_length;
             }

             // Discard if the source address is unspecified and
             // there is no source link-layer address option included.
             if (!got_macaddr && remote_endpoint_.address().is_unspecified()) {
                std::cerr << "Solicitation provides no specified source address or option." << std::endl;
                start_receive();
                return;
             }

             // Send a router advertisement in reply.
             try {
                 timer_.cancel();
                 send_advert(boost::optional<ba::ip::address_v6>());
                 // Unicast doesn't work.
                 //send_advert(remote_endpoint_.address().to_v6());
                 start_periodic_announce();
             } catch (const std::out_of_range &) {}

             start_receive();
         });
}


