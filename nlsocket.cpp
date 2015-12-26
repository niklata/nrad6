/* nlsocket.cpp - ipv6 netlink ifinfo gathering
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

#include <iostream>
#include "nlsocket.hpp"
#include "xorshift.hpp"
extern "C" {
#include "nl.h"
#include "nk/log.h"
}
namespace ba = boost::asio;
extern nk::rng::xorshift64m g_random_prng;

NLSocket::NLSocket(ba::io_service &io_service)
: socket_(io_service), nlseq_(g_random_prng())
{
    initialized_ = false;
    socket_.open(nl_protocol(NETLINK_ROUTE));
    socket_.bind(nl_endpoint<nl_protocol>(RTMGRP_LINK));
    socket_.non_blocking(true);

    request_links();
    request_addrs();
    initialized_ = true;

    // Begin the main asynchronous receive loop.
    start_receive();
}

void NLSocket::request_links()
{
    int fd = socket_.native();
    auto link_seq = nlseq_++;
    std::cerr << "send link_seq=" << link_seq << std::endl;
    if (nl_sendgetlinks(fd, link_seq) < 0)
        suicide("failed to get initial rtlink state");
    std::size_t bytes_xferred;
    boost::system::error_code ec;
    while ((bytes_xferred = socket_.receive(ba::buffer(recv_buffer_), 0, ec)))
        process_receive(bytes_xferred, link_seq, 0);
}

void NLSocket::request_addrs()
{
    int fd = socket_.native();
    auto addr_seq = nlseq_++;
    std::cerr << "send addr_seq=" << addr_seq << std::endl;
    if (nl_sendgetaddrs6(fd, addr_seq) < 0)
        suicide("failed to get initial rtaddr state");
    std::size_t bytes_xferred;
    boost::system::error_code ec;
    while ((bytes_xferred = socket_.receive(ba::buffer(recv_buffer_), 0, ec)))
        process_receive(bytes_xferred, addr_seq, 0);
}

void NLSocket::request_addrs(int ifidx)
{
    int fd = socket_.native();
    auto addr_seq = nlseq_++;
    if (nl_sendgetaddr6(fd, addr_seq, ifidx) < 0)
        suicide("failed to get initial rtaddr state");
}

void NLSocket::process_rt_addr_msgs(const struct nlmsghdr *nlh)
{
    auto ifa = reinterpret_cast<struct ifaddrmsg *>(NLMSG_DATA(nlh));
    struct rtattr *tb[IFA_MAX];
    memset(tb, 0, sizeof tb);
    nl_rtattr_parse(nlh, sizeof *ifa, rtattr_assign, tb);

    netif_addr nia;
    nia.addr_type = ifa->ifa_family;
    if (nia.addr_type != AF_INET6)
        return;
    nia.prefixlen = ifa->ifa_prefixlen;
    nia.flags = ifa->ifa_flags;
    nia.if_index = ifa->ifa_index;
    switch (ifa->ifa_scope) {
    case 0x0: nia.scope = netif_addr::Scope::Global; break;
    case 0x20: nia.scope = netif_addr::Scope::Link; break;
    default: log_warning("Unknown scope: %u", ifa->ifa_scope); return;
    }
    if (tb[IFA_ADDRESS]) {
        boost::asio::ip::address_v6::bytes_type bytes;
        memcpy(&bytes, RTA_DATA(tb[IFA_ADDRESS]), sizeof bytes);
        nia.address = boost::asio::ip::address_v6(bytes, ifa->ifa_scope);
    }
    if (tb[IFA_LOCAL]) {
        boost::asio::ip::address_v6::bytes_type bytes;
        memcpy(&bytes, RTA_DATA(tb[IFA_LOCAL]), sizeof bytes);
        nia.peer_address = boost::asio::ip::address_v6(bytes, ifa->ifa_scope);
    }
    if (tb[IFA_LABEL]) {
        auto v = reinterpret_cast<const char *>(RTA_DATA(tb[IFA_LABEL]));
        nia.if_name = std::string(v, strlen(v));
    }
    if (tb[IFA_BROADCAST]) {
        boost::asio::ip::address_v6::bytes_type bytes;
        memcpy(&bytes, RTA_DATA(tb[IFA_BROADCAST]), sizeof bytes);
        nia.broadcast_address = boost::asio::ip::address_v6(bytes,
                                                            ifa->ifa_scope);
    }
    if (tb[IFA_ANYCAST]) {
        boost::asio::ip::address_v6::bytes_type bytes;
        memcpy(&bytes, RTA_DATA(tb[IFA_ANYCAST]), sizeof bytes);
        nia.anycast_address = boost::asio::ip::address_v6(bytes,
                                                          ifa->ifa_scope);
    }

    switch (nlh->nlmsg_type) {
    case RTM_NEWADDR: {
        auto ifelt = interfaces.find(nia.if_index);
        if (ifelt == interfaces.end()) {
            log_warning("Address for unknown interface %s",
                        nia.if_name.c_str());
            return;
        }
        const auto iend = ifelt->second.addrs_v6.end();
        for (auto i = ifelt->second.addrs_v6.begin(); i != iend; ++i) {
            if (i->address == nia.address) {
                *i = std::move(nia);
                return;
            }
        }
        ifelt->second.addrs_v6.emplace_back(std::move(nia));
        return;
    }
    case RTM_DELADDR: {
        auto ifelt = interfaces.find(nia.if_index);
        if (ifelt == interfaces.end())
            return;
        const auto iend = ifelt->second.addrs_v6.end();
        for (auto i = ifelt->second.addrs_v6.begin(); i != iend; ++i) {
            if (i->address == nia.address) {
                ifelt->second.addrs_v6.erase(i);
                break;
            }
        }
        return;
    }
    default:
        log_warning("Unhandled address message type: %u", nlh->nlmsg_type);
        return;
    }
}

void NLSocket::process_rt_link_msgs(const struct nlmsghdr *nlh)
{
    auto ifm = reinterpret_cast<struct ifinfomsg *>(NLMSG_DATA(nlh));
    struct rtattr *tb[IFLA_MAX];
    memset(tb, 0, sizeof tb);
    nl_rtattr_parse(nlh, sizeof *ifm, rtattr_assign, tb);

    netif_info nii;
    nii.family = ifm->ifi_family;
    nii.device_type = ifm->ifi_type;
    nii.index = ifm->ifi_index;
    nii.flags = ifm->ifi_flags;
    nii.change_mask = ifm->ifi_change;
    nii.is_active = ifm->ifi_flags & IFF_UP;
    if (tb[IFLA_ADDRESS]) {
        auto mac = reinterpret_cast<const uint8_t *>
            (RTA_DATA(tb[IFLA_ADDRESS]));
        memcpy(nii.macaddr, mac, sizeof nii.macaddr);
    }
    if (tb[IFLA_BROADCAST]) {
        auto mac = reinterpret_cast<const uint8_t *>
            (RTA_DATA(tb[IFLA_ADDRESS]));
        memcpy(nii.macbc, mac, sizeof nii.macbc);
    }
    if (tb[IFLA_IFNAME]) {
        auto v = reinterpret_cast<const char *>(RTA_DATA(tb[IFLA_IFNAME]));
        nii.name = std::string(v, strlen(v));
    }
    if (tb[IFLA_QDISC]) {
        auto v = reinterpret_cast<const char *>(RTA_DATA(tb[IFLA_QDISC]));
        nii.qdisc = std::string(v, strlen(v));
    }
    if (tb[IFLA_MTU])
        nii.mtu = *reinterpret_cast<uint32_t *>(RTA_DATA(tb[IFLA_MTU]));
    if (tb[IFLA_LINK])
        nii.link_type = *reinterpret_cast<int32_t *>(RTA_DATA(tb[IFLA_LINK]));

    switch (nlh->nlmsg_type) {
    case RTM_NEWLINK: {
        name_to_ifindex_.emplace(std::make_pair(nii.name, nii.index));
        auto elt = interfaces.find(nii.index);
        // Preserve the addresses if we're just modifying fields.
        if (elt != interfaces.end())
            std::swap(nii.addrs_v6, elt->second.addrs_v6);
        std::cerr << "Adding link: " << nii.name << std::endl;
        interfaces.emplace(std::make_pair(nii.index, nii));
        if (initialized_)
            request_addrs(nii.index);
        break;
    }
    case RTM_DELLINK:
        name_to_ifindex_.erase(nii.name);
        interfaces.erase(nii.index);
        break;
    default:
        log_warning("Unhandled link message type: %u", nlh->nlmsg_type);
        break;
    }
}

void NLSocket::process_nlmsg(const struct nlmsghdr *nlh)
{
    switch(nlh->nlmsg_type) {
        case RTM_NEWLINK:
        case RTM_DELLINK:
            process_rt_link_msgs(nlh);
            break;
        case RTM_NEWADDR:
        case RTM_DELADDR:
            process_rt_addr_msgs(nlh);
            break;
        default:
            log_line("Unhandled RTNETLINK msg type: %u", nlh->nlmsg_type);
            break;
    }
}

void NLSocket::process_receive(std::size_t bytes_xferred,
                               unsigned int seq, unsigned int portid)
{
    const struct nlmsghdr *nlh = (const struct nlmsghdr *)recv_buffer_.data();
    for (;NLMSG_OK(nlh, bytes_xferred); nlh = NLMSG_NEXT(nlh, bytes_xferred)) {
        // Should be 0 for messages from the kernel.
        if (nlh->nlmsg_pid && portid && nlh->nlmsg_pid != portid)
            continue;
        if (seq && nlh->nlmsg_seq != seq)
            continue;

        if (nlh->nlmsg_type >= NLMSG_MIN_TYPE) {
            process_nlmsg(nlh);
        } else {
            switch (nlh->nlmsg_type) {
            case NLMSG_ERROR: {
                log_line("%s: Received a NLMSG_ERROR: %s",
                         __func__, strerror(nlmsg_get_error(nlh)));
                auto nle = reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(nlh));
                log_line("error=%d len=%u type=%u flags=%u seq=%u pid=%u",
                         nle->error, nle->msg.nlmsg_len, nle->msg.nlmsg_type,
                         nle->msg.nlmsg_flags, nle->msg.nlmsg_seq,
                         nle->msg.nlmsg_pid);
                break;
            }
            case NLMSG_OVERRUN:
                log_line("%s: Received a NLMSG_OVERRUN.", __func__);
            case NLMSG_NOOP:
            case NLMSG_DONE:
            default:
                break;
            }
        }
    }
}

void NLSocket::start_receive()
{
    socket_.async_receive_from
        (ba::buffer(recv_buffer_), remote_endpoint_,
         [this](const boost::system::error_code &error,
                std::size_t bytes_xferred)
         {
             process_receive(bytes_xferred, 0, 0);
             start_receive();
         });
}


