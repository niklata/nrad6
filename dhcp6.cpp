#include <nk/format.hpp>
#include "nlsocket.hpp"
#include "multicast6.hpp"
#include "dhcp6.hpp"
#include "attach_bpf.h"

namespace ba = boost::asio;

extern std::unique_ptr<NLSocket> nl_socket;
static auto mc6_alldhcp_ras = ba::ip::address_v6::from_string("ff02::1:2");

D6Listener::D6Listener(ba::io_service &io_service,
                       const std::string &ifname)
  : socket_(io_service), ifname_(ifname), using_bpf_(false)
{
    int ifidx = nl_socket->get_ifindex(ifname_);
    const auto &ifinfo = nl_socket->interfaces.at(ifidx);
    memcpy(macaddr_, ifinfo.macaddr, sizeof macaddr_);

    socket_.open(ba::ip::udp::v6());
    auto lla_ep = ba::ip::udp::endpoint(ba::ip::address_v6::any(), 547);
    attach_multicast(socket_.native(), ifname, mc6_alldhcp_ras);
    attach_bpf(socket_.native());
    socket_.bind(lla_ep);

    for (const auto &i: ifinfo.addrs) {
        if (i.scope == netif_addr::Scope::Global && i.address.is_v6()) {
            local_ip_ = i.address.to_v6();
            fmt::print(stderr, "IP address for {} is {}.\n", ifname, local_ip_);
        }
    }
    radv6_listener_ = std::make_unique<RA6Listener>(io_service, ifname);

    start_receive();
}

void D6Listener::attach_bpf(int fd)
{
    //using_bpf_ = attach_bpf_dhcp6_info(fd, ifname_.c_str());
}

static const char * dhcp6_msgtype_to_string(dhcp6_msgtype m)
{
    switch (m) {
    default: return "unknown";
    case dhcp6_msgtype::solicit: return "solicit";
    case dhcp6_msgtype::advertise: return "advertise";
    case dhcp6_msgtype::request: return "request";
    case dhcp6_msgtype::confirm: return "confirm";
    case dhcp6_msgtype::renew: return "renew";
    case dhcp6_msgtype::rebind: return "rebind";
    case dhcp6_msgtype::reply: return "reply";
    case dhcp6_msgtype::release: return "release";
    case dhcp6_msgtype::decline: return "decline";
    case dhcp6_msgtype::reconfigure: return "reconfigure";
    case dhcp6_msgtype::information_request: return "information_request";
    case dhcp6_msgtype::relay_forward: return "relay_forward";
    case dhcp6_msgtype::relay_reply: return "relay_reply";
    }
}

static const char * dhcp6_opt_to_string(uint16_t opttype)
{
    switch (opttype) {
    case  1: return "Client Identifier";
    case  2: return "Server Identifier";
    case  3: return "Identity Association (IA) Non-Temporary";
    case  4: return "Identity Association (IA) Temporary";
    case  5: return "Identity Association (IA) Address";
    case  6: return "Option Request";
    case  7: return "Preference";
    case  8: return "Elapsed Time";
    case  9: return "Relay Message";
    case 11: return "Authentication";
    case 12: return "Server Unicast";
    case 13: return "Status Code";
    case 14: return "Rapid Commit";
    case 15: return "User Class";
    case 16: return "Vendor Class";
    case 17: return "Vendor Options";
    case 18: return "Interface ID";
    case 19: return "Reconfigure Message";
    case 20: return "Reconfigure Accept";
    case 23: return "DNS Recursive Servers"; // RFC3646
    case 24: return "DNS Domain Search List"; // RFC3646
    case 39: return "Client FQDN"; // RFC4704
    case 56: return "NTP Server"; // RFC5908
    default:
             fmt::print("Unknown DHCP Option type: {}\n", opttype);
             return "Unknown";
    }
}

void D6Listener::write_response_header(const d6msg_state &d6s, std::ostream &os,
                                       dhcp6_msgtype mtype)
{
    dhcp6_header send_d6hdr;
    send_d6hdr.msg_type(mtype);
    send_d6hdr.xid(d6s.header.xid());
    os << send_d6hdr;

    dhcp6_opt_serverid send_serverid(macaddr_);
    os << send_serverid;

    if (d6s.client_duid_blob.size()) {
        dhcp6_opt send_clientid;
        send_clientid.type(1);
        send_clientid.length(d6s.client_duid_blob.size());
        os << send_clientid;
        for (const auto &i: d6s.client_duid_blob)
            os << i;
    }
}

void D6Listener::emit_address(const d6msg_state &d6s, std::ostream &os, const dhcpv6_entry *v)
{
    dhcp6_opt header;
    header.type(3);
    header.length(d6_ia::size + dhcp6_opt::size + d6_ia_addr::size);
    os << header;
    d6_ia ia;
    ia.iaid = v->iaid;
    ia.t1_seconds = static_cast<uint32_t>(0.5 * v->lifetime);
    ia.t2_seconds = static_cast<uint32_t>(0.8 * v->lifetime);
    os << ia;
    header.type(5);
    header.length(d6_ia_addr::size);
    os << header;
    d6_ia_addr addr;
    addr.addr = v->address;
    addr.prefer_lifetime = v->lifetime;
    addr.valid_lifetime = v->lifetime;
    os << addr;
}

bool D6Listener::attach_address_info(const d6msg_state &d6s, std::ostream &os)
{
    bool ret{false};
    // Look through IAs and send IA with assigned address as an option.
    for (const auto &i: d6s.ias) {
        printf("Querying duid='%s' iaid=%u...\n", d6s.client_duid.c_str(), i.iaid);
        auto x = query_dhcp_state(ifname_, d6s.client_duid, i.iaid);
        if (x) {
            ret = true;
            fmt::print("Found address: {}\n", x->address.to_string());
            emit_address(d6s, os, x);
        } else {
            fmt::print("Unknown DUID={} IAID={} from addr={}\n",
                       d6s.client_duid, i.iaid, sender_endpoint_.address().to_string());
        }
    }
    if (!ret)
        fmt::print("No info!\n");
    return ret;
}

// If opt_req.size() == 0 then send DnsServers, DomainList,
// and NtpServer.  Otherwise, for each of these types,
// see if it is in the opt_req before adding it to the reply.
void D6Listener::attach_dns_ntp_info(const d6msg_state &d6s, std::ostream &os)
{
    const auto dns6_servers = query_dns6_servers(ifname_);
    if ((!d6s.optreq_exists || d6s.optreq_dns) && dns6_servers.size()) {
        dhcp6_opt send_dns;
        send_dns.type(23);
        send_dns.length(dns6_servers.size() * 16);
        os << send_dns;
        for (const auto &i: dns6_servers) {
            const auto d6b = i.to_bytes();
            for (const auto &j: d6b)
                os << j;
        }
    }
    const auto dns6_search_blob = query_dns6_search_blob(ifname_);
    if ((!d6s.optreq_exists || d6s.optreq_dns_search)
        && dns6_search_blob.size()) {
        dhcp6_opt send_dns_search;
        send_dns_search.type(24);
        send_dns_search.length(dns6_search_blob.size());
        os << send_dns_search;
        for (const auto &i: dns6_search_blob)
            os << i;
    }
    const auto ntp6_servers = query_ntp6_servers(ifname_);
    const auto ntp6_multicasts = query_ntp6_multicasts(ifname_);
    const auto ntp6_fqdns_blob = query_ntp6_fqdns_blob(ifname_);
    const auto n6s_size = ntp6_servers.size();
    const auto n6m_size = ntp6_multicasts.size();
    const auto n6d_size = ntp6_fqdns_blob.size();
    if ((!d6s.optreq_exists || d6s.optreq_ntp)
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
            const auto n6b = i.to_bytes();
            for (const auto &j: n6b)
                os << j;
        }
        for (const auto &i: ntp6_multicasts) {
            uint16_t soc(2);
            uint16_t sol(16);
            os << soc << sol;
            const auto n6b = i.to_bytes();
            for (const auto &j: n6b)
                os << j;
        }
        for (const auto &i: ntp6_fqdns_blob)
            os << i;
    }
    if (d6s.optreq_sntp) {
        uint16_t len(0);
        dhcp6_opt send_sntp;
        send_sntp.type(31);
        if (n6s_size)
            len += n6s_size * 16;
        send_sntp.length(len);
        for (const auto &i: ntp6_servers) {
            const auto n6b = i.to_bytes();
            for (const auto &j: n6b)
                os << j;
        }
    }
}

void D6Listener::handle_solicit_msg(const d6msg_state &d6s, ba::streambuf &send_buffer)
{
    std::ostream os(&send_buffer);
    write_response_header(d6s, os, !d6s.use_rapid_commit ? dhcp6_msgtype::advertise
                                                         : dhcp6_msgtype::reply);

    attach_address_info(d6s, os);
    attach_dns_ntp_info(d6s, os);

    if (d6s.use_rapid_commit) {
        dhcp6_opt rapid_commit;
        rapid_commit.type(14);
        rapid_commit.length(0);
        os << rapid_commit;
    }
}

void D6Listener::handle_request_msg(const d6msg_state &d6s, ba::streambuf &send_buffer)
{
    std::ostream os(&send_buffer);
    write_response_header(d6s, os, dhcp6_msgtype::reply);

    attach_address_info(d6s, os);
    attach_dns_ntp_info(d6s, os);
}

bool D6Listener::confirm_match(const d6msg_state &d6s) const
{
    for (const auto &i: d6s.ias) {
        printf("Querying duid='%s' iaid=%u...\n", d6s.client_duid.c_str(), i.iaid);
        auto x = query_dhcp_state(ifname_, d6s.client_duid, i.iaid);
        if (x) {
            fmt::print("Found a possible match for an IA.\n");
            bool found_addr{false};
            for (const auto &j: i.ia_na_addrs) {
                if (j.addr == x->address)
                    found_addr = true;
            }
            if (!found_addr) {
                fmt::print("Mismatched address. NAK.\n");
                return false;
            }
        } else {
            fmt::print("Unknown DUID={} IAID={} from addr={}. NAK.\n",
                       d6s.client_duid, i.iaid, sender_endpoint_.address().to_string());
            return false;
        }
    }
    fmt::print("Everything matches and is OK.\n");
    return true;
}

void D6Listener::handle_confirm_msg(const d6msg_state &d6s, boost::asio::streambuf &send_buffer)
{
    std::ostream os(&send_buffer);
    write_response_header(d6s, os, dhcp6_msgtype::reply);

    bool all_ok = confirm_match(d6s);

    // Write Status Code Success or NotOnLink.
    char ok_str[] = "ACK";
    char nak_str[] = "NAK";
    dhcp6_opt header;
    header.type(13);
    header.length(5);
    os << header;
    d6_statuscode sc(all_ok ? d6_statuscode::code::success : d6_statuscode::code::notonlink);
    os << sc;
    if (all_ok) {
        for (int i = 0; ok_str[i]; ++i)
            os << ok_str[i];
    } else {
        for (int i = 0; nak_str[i]; ++i)
            os << nak_str[i];
    }

    attach_dns_ntp_info(d6s, os);
}

void D6Listener::handle_renew_msg(const d6msg_state &d6s, boost::asio::streambuf &send_buffer)
{
    std::ostream os(&send_buffer);
    write_response_header(d6s, os, dhcp6_msgtype::reply);

    // XXX: Write Status Code NoBinding if no record exists.
    attach_address_info(d6s, os);
    attach_dns_ntp_info(d6s, os);
}

void D6Listener::handle_rebind_msg(const d6msg_state &d6s, boost::asio::streambuf &send_buffer)
{
    std::ostream os(&send_buffer);
    write_response_header(d6s, os, dhcp6_msgtype::reply);

    attach_address_info(d6s, os);
    attach_dns_ntp_info(d6s, os);
}

void D6Listener::handle_information_msg(const d6msg_state &d6s, ba::streambuf &send_buffer)
{
    std::ostream os(&send_buffer);
    write_response_header(d6s, os, dhcp6_msgtype::reply);
    attach_dns_ntp_info(d6s, os);
    fmt::print("Sending Information Message in response.\n");
}

#define BYTES_LEFT_DEC(BLD_VAL) bytes_left_dec(d6s, bytes_left, (BLD_VAL))

#define CONSUME_OPT(CO_MSG) \
         fmt::print(stderr, (CO_MSG)); \
         while (l--) { \
             is.get(); \
             BYTES_LEFT_DEC(1); \
         } \
         continue

size_t D6Listener::bytes_left_dec(d6msg_state &d6s, std::size_t &bytes_left, size_t v) {
    if (bytes_left < v)
        throw std::out_of_range("bytes_left would underflow\n");
    bytes_left -= v;
    size_t option_depth{0};
    for (auto &i: d6s.prev_opt) {
        ++option_depth;
        if (i.second < v)
            throw std::out_of_range(fmt::format("{} depth would underflow\n", option_depth));
        i.second -= v;
    }
    while (!d6s.prev_opt.empty() && d6s.prev_opt.back().second == 0)
        d6s.prev_opt.pop_back();
    option_depth = 0;
    for (const auto &i: d6s.prev_opt) {
        ++option_depth;
        // Tricky: Guard against client sending invalid suboption lengths.
        if (i.second <= 0)
            throw std::out_of_range(fmt::format("{} depth ran out of length but has suboption size left\n"));
    }
    return bytes_left;
}

void D6Listener::start_receive()
{
    recv_buffer_.consume(recv_buffer_.size());
    socket_.async_receive_from
        (recv_buffer_.prepare(8192), sender_endpoint_,
         [this](const boost::system::error_code &error, std::size_t bytes_xferred)
         {
             fmt::print(stderr, "\nbytes_xferred={}\n", bytes_xferred);
             recv_buffer_.commit(bytes_xferred);

             // XXX: This stanza can probably be thrown away.
             auto seps = sender_endpoint_.address().to_string();
             const auto seps_ifr = seps.find_last_of('%');
             if (seps_ifr != std::string::npos) {
                 auto xx = seps.substr(seps_ifr + 1);
                 if (xx != ifname_)
                     throw std::logic_error("ifname doesn't match");
             }

             std::size_t bytes_left = bytes_xferred;
             if (!using_bpf_) {
                 // Discard if the DHCP6 length < the size of a DHCP6 header.
                 if (bytes_xferred < dhcp6_header::size) {
                    fmt::print(stderr, "DHCP6 from {} is too short: {}\n",
                               sender_endpoint_, bytes_xferred);
                    start_receive();
                    return;
                 }
             }

             std::istream is(&recv_buffer_);
             d6msg_state d6s;
             is >> d6s.header;
             BYTES_LEFT_DEC(dhcp6_header::size);

             fmt::print(stderr, "DHCP Message: {}\n",
                        dhcp6_msgtype_to_string(d6s.header.msg_type()));

             // These message types are not allowed to be sent to servers.
             switch (d6s.header.msg_type()) {
             case dhcp6_msgtype::advertise:
             case dhcp6_msgtype::reply:
             case dhcp6_msgtype::reconfigure:
             case dhcp6_msgtype::relay_reply:
                 start_receive(); return;
             default: break;
             }

             while (bytes_left >= 4) {
                 //fmt::print(stderr, "bytes_left={}\n", bytes_left);
                 dhcp6_opt opt;
                 is >> opt;
                 fmt::print(stderr, "Option: '{}' length={}\n",
                            dhcp6_opt_to_string(opt.type()), opt.length());
                 BYTES_LEFT_DEC(dhcp6_opt::size);
                 auto l = opt.length();
                 auto ot = opt.type();

                 if (l > bytes_left) {
                     fmt::print(stderr, "Option is too long.\n");
                     while (bytes_left) {
                         BYTES_LEFT_DEC(1);
                         is.get();
                     }
                     continue;
                 }

                 if (ot == 1) { // ClientID
                     d6s.client_duid_blob.reserve(l);
                     d6s.client_duid.reserve(2*l);
                     while (l--) {
                         uint8_t c = is.get();
                         d6s.client_duid_blob.push_back(c);
                         d6s.client_duid.append(fmt::sprintf("%02.x", c));
                         BYTES_LEFT_DEC(1);
                     }
                     if (d6s.client_duid.size() > 0)
                        fmt::print("\tDUID: {}\n", d6s.client_duid);
                 } else if (ot == 3) { // Option_IA_NA
                     if (l < 12) {
                         CONSUME_OPT("Client-sent option IA_NA has a bad length.  Ignoring.\n");
                     }
                     d6s.ias.emplace_back();
                     is >> d6s.ias.back();
                     BYTES_LEFT_DEC(d6_ia::size);

                     const auto na_options_len = l - 12;
                     if (na_options_len > 0)
                         d6s.prev_opt.emplace_back(std::make_pair(3, na_options_len));

                     fmt::printf("\tIA_NA: iaid=%u t1=%us t2=%us opt_len=%u\n",
                                d6s.ias.back().iaid, d6s.ias.back().t1_seconds,
                                d6s.ias.back().t2_seconds, na_options_len);
                 } else if (ot == 5) { // Address
                     if (l < 24) {
                         CONSUME_OPT("Client-sent option IAADDR has a bad length.  Ignoring.\n");
                     }
                     if (d6s.prev_opt.size() != 1) {
                         CONSUME_OPT("Client-sent option IAADDR is not nested.  Ignoring.\n");
                     }
                     if (d6s.prev_opt.back().first != 3) {
                         CONSUME_OPT("Client-sent option IAADDR must follow IA_NA.  Ignoring.\n");
                     }
                     if (d6s.ias.empty())
                         throw std::logic_error("d6.ias is empty");
                     d6s.ias.back().ia_na_addrs.emplace_back();
                     if (d6s.ias.back().ia_na_addrs.empty())
                         throw std::logic_error("d6.ias.back().ia_na_addrs is empty");
                     is >> d6s.ias.back().ia_na_addrs.back();
                     BYTES_LEFT_DEC(d6_ia_addr::size);

                     auto iaa_options_len = l - 24;
                     if (iaa_options_len > 0)
                         d6s.prev_opt.emplace_back(std::make_pair(5, iaa_options_len));

                     fmt::print("\tIA Address: {} prefer={}s valid={}s opt_len={}\n",
                                d6s.ias.back().ia_na_addrs.back().addr.to_string(),
                                d6s.ias.back().ia_na_addrs.back().prefer_lifetime,
                                d6s.ias.back().ia_na_addrs.back().valid_lifetime,
                                iaa_options_len);

                 } else if (ot == 6) { // OptionRequest
                     if (l % 2) {
                         CONSUME_OPT("Client-sent option Request has a bad length.  Ignoring.\n");
                     }
                     d6s.optreq_exists = true;
                     l /= 2;
                     while (l--) {
                         char b[2];
                         b[1] = is.get();
                         b[0] = is.get();
                         BYTES_LEFT_DEC(2);
                         uint16_t v;
                         memcpy(&v, b, 2);
                         fmt::print("Option Request:");
                         switch (v) {
                         case 23: d6s.optreq_dns = true; fmt::print(" DNS"); break;
                         case 24: d6s.optreq_dns_search = true; fmt::print(" DNS_SEARCH"); break;
                         case 31: d6s.optreq_sntp = true; fmt::print(" SNTP"); break;
                         case 32: d6s.optreq_info_refresh_time = true; fmt::print(" INFO_REFRESH"); break;
                         case 56: d6s.optreq_ntp = true; fmt::print(" NTP"); break;
                         default: fmt::print(" {}", v); break;
                         }
                         fmt::print("\n");
                     }
                     fmt::print("\tOptions requested: dns={} dns_search={} info_refresh={} ntp={}\n",
                                d6s.optreq_dns, d6s.optreq_dns_search,
                                d6s.optreq_info_refresh_time, d6s.optreq_ntp);
                 } else if (ot == 8) { // ElapsedTime
                     // 16-bit hundreths of a second since start of exchange
                     if (l != 2) {
                         CONSUME_OPT("Client-sent option ElapsedTime has a bad length.  Ignoring.\n");
                     }
                     char b[2];
                     b[1] = is.get();
                     b[0] = is.get();
                     BYTES_LEFT_DEC(2);
                     memcpy(&d6s.elapsed_time, b, 2);
                 } else if (ot == 14) { // Rapid Commit
                     if (l != 0) {
                         CONSUME_OPT("Client-sent option Rapid Commit has a bad length.  Ignoring.\n");
                     }
                     d6s.use_rapid_commit = true;
                 } else if (ot == 39) { // Client FQDN
                     fmt::print("\tFQDN Length: {}\n", l);
                     if (l < 3) {
                         CONSUME_OPT("Client-sent option Client FQDN has a bad length.  Ignoring.\n");
                     }
                     char flags;
                     uint8_t namelen;
                     flags = is.get();
                     namelen = is.get();
                     BYTES_LEFT_DEC(2);
                     l -= 2;
                     if (l != namelen) {
                         CONSUME_OPT("Client-sent option Client FQDN namelen disagrees with length.  Ignoring.\n");
                     }
                     d6s.fqdn_.clear();
                     d6s.fqdn_.reserve(namelen);
                     fmt::print("\tFQDN Flags='{}', NameLen='{}'\n", +flags, +namelen);
                     while (l--) {
                        char c;
                        c = is.get();
                        BYTES_LEFT_DEC(1);
                        d6s.fqdn_.push_back(c);
                     }
                     fmt::print("\tClient FQDN: flags={} '{}'\n",
                                static_cast<uint8_t>(flags), d6s.fqdn_);
                 } else {
                     while (l--) {
                         is.get();
                         BYTES_LEFT_DEC(1);
                     }
                 }
             }

             ba::streambuf send_buffer;
             switch (d6s.header.msg_type()) {
             case dhcp6_msgtype::solicit:
                 handle_solicit_msg(d6s, send_buffer); break;
             case dhcp6_msgtype::request:
                 handle_request_msg(d6s, send_buffer); break;
             case dhcp6_msgtype::confirm:
                 handle_confirm_msg(d6s, send_buffer); break;
             case dhcp6_msgtype::renew:
                 handle_renew_msg(d6s, send_buffer); break;
             case dhcp6_msgtype::rebind:
                 handle_rebind_msg(d6s, send_buffer); break;
             case dhcp6_msgtype::information_request:
                 handle_information_msg(d6s, send_buffer); break;
             default: start_receive(); return;
             }

             fmt::print("Calling send_to => {}\n", sender_endpoint_.address().to_string());

             boost::system::error_code ec;
             socket_.send_to(send_buffer.data(), sender_endpoint_, 0, ec);
             start_receive();
         });
}

