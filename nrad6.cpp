/* nrad6.c - ipv6 router advertisement and dhcp server
 *
 * (c) 2014-2016 Nicholas J. Kain <njkain at gmail dot com>
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

#define NRAD6_VERSION "0.5"

#include <memory>
#include <string>
#include <vector>
#include <random>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <errno.h>
#include <boost/asio.hpp>
#include <nk/format.hpp>
#include <nk/optionarg.hpp>
#include <nk/str_to_int.hpp>
#include <nk/xorshift.hpp>
extern "C" {
#include "nk/log.h"
#include "nk/privilege.h"
#include "nk/pidfile.h"
#include "nk/seccomp-bpf.h"
}
#include "nlsocket.hpp"
#include "dhcp6.hpp"
#include "dhcp4.hpp"
#include "dhcp_state.hpp"
#include "dynlease.hpp"

boost::asio::io_service io_service;
static boost::asio::signal_set asio_signal_set(io_service);
static std::string configfile{"/etc/nrad6.conf"};
static uid_t nrad6_uid;
static gid_t nrad6_gid;
static bool use_seccomp(false);

std::unique_ptr<NLSocket> nl_socket;

static std::vector<std::unique_ptr<D6Listener>> v6_listeners;
static std::vector<std::unique_ptr<D4Listener>> v4_listeners;

static std::random_device g_random_secure;
nk::rng::xorshift64m g_random_prng(0);

static std::string leasefile;

extern void parse_config(const std::string &path);

static void init_prng()
{
    std::array<uint32_t, nk::rng::xorshift64m::state_size> seed_data;
    std::generate_n(seed_data.data(), seed_data.size(),
                    std::ref(g_random_secure));
    std::seed_seq seed_seq(std::begin(seed_data), std::end(seed_data));
    g_random_prng.seed(seed_seq);
}

static void init_listeners()
{
    auto ios = &io_service;
    auto v6l = &v6_listeners;
    auto v4l = &v4_listeners;
    bound_interfaces_foreach([ios, v6l, v4l](const std::string &i, bool use_v4, bool use_v6) {
        if (use_v6) {
            try {
                v6l->emplace_back(std::make_unique<D6Listener>(*ios, i));
            } catch (const std::out_of_range &exn) {
                fmt::print(stderr, "Can't bind to v6 interface: {}\n", i);
            }
        }
        if (use_v4) {
            try {
                v4l->emplace_back(std::make_unique<D4Listener>(*ios, i));
            } catch (const boost::system::error_code &) {
                fmt::print(stderr, "Can't bind to v4 interface: {}\n", i);
            }
        }
    });
}

static void process_signals()
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGPIPE);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGTSTP);
    sigaddset(&mask, SIGTTIN);
    sigaddset(&mask, SIGHUP);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        fmt::print(stderr, "sigprocmask failed\n");
        std::exit(EXIT_FAILURE);
    }
    asio_signal_set.add(SIGINT);
    asio_signal_set.add(SIGTERM);
    asio_signal_set.async_wait(
        [](const boost::system::error_code &, int signum) {
            io_service.stop();
        });
}

static int enforce_seccomp(bool changed_uidgid)
{
    if (!use_seccomp)
        return 0;
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        EXAMINE_SYSCALL,
        ALLOW_SYSCALL(epoll_wait),
        ALLOW_SYSCALL(sendmsg),
        ALLOW_SYSCALL(recvmsg),
        ALLOW_SYSCALL(timerfd_settime),
        ALLOW_SYSCALL(epoll_ctl),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(sendto), // used for glibc syslog routines
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(rt_sigreturn),
        ALLOW_SYSCALL(rt_sigaction),
#ifdef __NR_sigreturn
        ALLOW_SYSCALL(sigreturn),
#endif
#ifdef __NR_sigaction
        ALLOW_SYSCALL(sigaction),
#endif
        // Allowed by vDSO
        ALLOW_SYSCALL(getcpu),
        ALLOW_SYSCALL(time),
        ALLOW_SYSCALL(gettimeofday),
        ALLOW_SYSCALL(clock_gettime),

        // operator new
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(munmap),

        ALLOW_SYSCALL(fstat),

        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(exit),
        KILL_PROCESS,
    };
    struct sock_fprog prog;
    memset(&prog, 0, sizeof prog);
    prog.len = (unsigned short)(sizeof filter / sizeof filter[0]);
    prog.filter = filter;
    if (!changed_uidgid && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return -1;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
        return -1;
    fmt::print("seccomp filter installed.  Please disable seccomp if you encounter problems.\n");
    std::fflush(stdout);
    return 0;
}

static void print_version(void)
{
    fmt::print("nrad6 " NRAD6_VERSION ", ipv6 router advertisment and dhcp server.\n"
               "Copyright (c) 2014-2016 Nicholas J. Kain\n"
               "All rights reserved.\n\n"
               "Redistribution and use in source and binary forms, with or without\n"
               "modification, are permitted provided that the following conditions are met:\n\n"
               "- Redistributions of source code must retain the above copyright notice,\n"
               "  this list of conditions and the following disclaimer.\n"
               "- Redistributions in binary form must reproduce the above copyright notice,\n"
               "  this list of conditions and the following disclaimer in the documentation\n"
               "  and/or other materials provided with the distribution.\n\n"
               "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\"\n"
               "AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\n"
               "IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE\n"
               "ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE\n"
               "LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR\n"
               "CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF\n"
               "SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS\n"
               "INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN\n"
               "CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)\n"
               "ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE\n"
               "POSSIBILITY OF SUCH DAMAGE.\n");
}

enum OpIdx {
    OPT_UNKNOWN, OPT_HELP, OPT_VERSION, OPT_BACKGROUND, OPT_CONFIG,
    OPT_LEASEFILE, OPT_PIDFILE, OPT_CHROOT, OPT_USER, OPT_SECCOMP, OPT_QUIET
};
static const option::Descriptor usage[] = {
    { OPT_UNKNOWN,    0,  "",           "", Arg::Unknown,
        "nrad6 " NRAD6_VERSION ", DHCPv4/DHCPv6 and IPv6 Router Advertisement server.\n"
        "Copyright (c) 2014-2016 Nicholas J. Kain\n"
        "nrad6 [options] [configfile]...\n\nOptions:" },
    { OPT_HELP,       0, "h",            "help",    Arg::None, "\t-h, \t--help  \tPrint usage and exit." },
    { OPT_VERSION,    0, "v",         "version",    Arg::None, "\t-v, \t--version  \tPrint version and exit." },
    { OPT_BACKGROUND, 0, "b",      "background",    Arg::None, "\t-b, \t--background  \tRun as a background daemon." },
    { OPT_CONFIG,     0, "c",          "config",  Arg::String, "\t-c, \t--config  \tPath to configuration file (default: /etc/nrad6.conf)."},
    { OPT_LEASEFILE,  0, "l",       "leasefile",  Arg::String, "\t-l, \t--leasefile  \tPath to lease file (path relative to chroot if it exists)." },
    { OPT_PIDFILE,    0, "f",         "pidfile",  Arg::String, "\t-f, \t--pidfile  \tPath to process id file." },
    { OPT_CHROOT,     0, "C",          "chroot",  Arg::String, "\t-C, \t--chroot  \tPath in which nident should chroot itself." },
    { OPT_USER,       0, "u",            "user",  Arg::String, "\t-u, \t--user  \tUser name that nrad6 should run as." },
    { OPT_SECCOMP,    0, "S", "seccomp-enforce",    Arg::None, "\t    \t--seccomp-enforce  \tEnforce seccomp syscall restrictions." },
    { OPT_QUIET,      0, "q",           "quiet",    Arg::None, "\t-q, \t--quiet  \tDon't log to std(out|err) or syslog." },
    {0,0,0,0,0,0}
};
static void process_options(int ac, char *av[])
{
    ac-=ac>0; av+=ac>0;
    option::Stats stats(usage, ac, av);
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvla"
    option::Option options[stats.options_max], buffer[stats.buffer_max];
#pragma GCC diagnostic pop
    option::Parser parse(usage, ac, av, options, buffer);
#else
    auto options = std::make_unique<option::Option[]>(stats.options_max);
    auto buffer = std::make_unique<option::Option[]>(stats.buffer_max);
    option::Parser parse(usage, ac, av, options.get(), buffer.get());
#endif
    if (parse.error())
        std::exit(EXIT_FAILURE);
    if (options[OPT_HELP]) {
        uint16_t col{80};
        const auto cols = getenv("COLUMNS");
        if (cols) col = nk::str_to_u16(cols);
        option::printUsage(fwrite, stdout, usage, col);
        std::exit(EXIT_FAILURE);
    }
    if (options[OPT_VERSION]) {
        print_version();
        std::exit(EXIT_FAILURE);
    }

    std::vector<std::string> addrlist;
    std::string pidfile, chroot_path;

    for (int i = 0; i < parse.optionsCount(); ++i) {
        option::Option &opt = buffer[i];
        switch (opt.index()) {
            case OPT_BACKGROUND: gflags_detach = 1; break;
            case OPT_CONFIG: configfile = std::string(opt.arg); break;
            case OPT_LEASEFILE: leasefile = std::string(opt.arg); break;
            case OPT_PIDFILE: pidfile = std::string(opt.arg); break;
            case OPT_CHROOT: chroot_path = std::string(opt.arg); break;
            case OPT_USER: {
                if (nk_uidgidbyname(opt.arg, &nrad6_uid, &nrad6_gid)) {
                    fmt::print(stderr, "invalid user '{}' specified\n", opt.arg);
                    std::exit(EXIT_FAILURE);
                }
                break;
            }
            case OPT_SECCOMP: use_seccomp = true; break;
            case OPT_QUIET: gflags_quiet = 1; break;
        }
    }

    init_prng();
    if (configfile.size())
        parse_config(configfile);

    for (int i = 0; i < parse.nonOptionsCount(); ++i)
        parse_config(parse.nonOption(i));

    if (!bound_interfaces_count()) {
        fmt::print(stderr, "No interfaces have been bound\n");
        std::exit(EXIT_FAILURE);
    }

    if (!leasefile.size()) {
        leasefile = chroot_path.size() ? "/store/dynlease.txt"
                                       : "/var/lib/ndhs/store/dynlease.txt";
    }

    nl_socket = std::make_unique<NLSocket>(io_service);
    init_listeners();

    if (gflags_detach && daemon(0,0)) {
        fmt::print(stderr, "detaching fork failed\n");
        std::exit(EXIT_FAILURE);
    }

    if (pidfile.size() && file_exists(pidfile.c_str(), "w"))
        write_pid(pidfile.c_str());

    umask(077);
    process_signals();

    if (chroot_path.size()) {
        nk_set_chroot(chroot_path.c_str());
    }
    dynlease_deserialize(leasefile);
    if (nrad6_uid || nrad6_gid)
        nk_set_uidgid(nrad6_uid, nrad6_gid, NULL, 0);

    if (enforce_seccomp(nrad6_uid || nrad6_gid)) {
        fmt::print(stderr, "seccomp filter cannot be installed\n");
        std::exit(EXIT_FAILURE);
    }
}

int main(int ac, char *av[])
{
    gflags_log_name = const_cast<char *>("nrad6");

    process_options(ac, av);

    io_service.run();

    dynlease_serialize(leasefile);

    std::exit(EXIT_SUCCESS);
}

