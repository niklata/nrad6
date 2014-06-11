/* nrad6.c - ipv6 router advertisement and dhcp server
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

#define NRAD6_VERSION "0.5"

#include <memory>
#include <string>
#include <vector>
#include <fstream>

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
#include <getopt.h>

#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <boost/random/random_device.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/variate_generator.hpp>

#include "make_unique.hpp"
#include "nlsocket.hpp"
#include "radv6.hpp"

extern "C" {
#include "nk/log.h"
#include "nk/privilege.h"
#include "nk/pidfile.h"
#include "nk/seccomp-bpf.h"
}

namespace po = boost::program_options;

boost::asio::io_service io_service;
static boost::asio::signal_set asio_signal_set(io_service);
static uid_t nrad6_uid;
static gid_t nrad6_gid;

static boost::random::random_device g_random_secure;
boost::random::mt19937 g_random_prng(g_random_secure());

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
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
        suicide("sigprocmask failed");
    asio_signal_set.add(SIGINT);
    asio_signal_set.add(SIGTERM);
    asio_signal_set.async_wait(
        [](const boost::system::error_code &, int signum) {
            io_service.stop();
        });
}

#if 0
// XXX: This is not updated for nrad6.
static int enforce_seccomp(void)
{
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        EXAMINE_SYSCALL,
        ALLOW_SYSCALL(sendmsg),
        ALLOW_SYSCALL(recvmsg),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(sendto), // used for glibc syslog routines
        ALLOW_SYSCALL(epoll_wait),
        ALLOW_SYSCALL(epoll_ctl),
        ALLOW_SYSCALL(getpeername),
        ALLOW_SYSCALL(getsockname),
        ALLOW_SYSCALL(stat),
        ALLOW_SYSCALL(open),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(connect),
        ALLOW_SYSCALL(socket),
        ALLOW_SYSCALL(accept),
        ALLOW_SYSCALL(ioctl),
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

        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(exit),
        KILL_PROCESS,
    };
    struct sock_fprog prog;
    memset(&prog, 0, sizeof prog);
    prog.len = (unsigned short)(sizeof filter / sizeof filter[0]);
    prog.filter = filter;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return -1;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
        return -1;
    return 0;
}
#endif

static po::variables_map fetch_options(int ac, char *av[])
{
    std::string config_file;

    po::options_description cli_opts("Command-line-exclusive options");
    cli_opts.add_options()
        ("config,c", po::value<std::string>(&config_file),
         "path to configuration file")
        ("background", "run as a background daemon")
        ("verbose,V", "print details of normal operation")
        ("help,h", "print help message")
        ("version,v", "print version information")
        ;

    po::options_description gopts("Options");
    gopts.add_options()
        ("pidfile,f", po::value<std::string>(),
         "path to process id file")
        ("chroot,C", po::value<std::string>(),
         "path in which nrad6 should chroot itself")
        ("interface,i", po::value<std::vector<std::string> >()->composing(),
         "'interface' on which to act as a router (default none)")
        ("user,u", po::value<std::string>(),
         "user name that nrad6 should run as")
        ;

    po::options_description cmdline_options;
    cmdline_options.add(cli_opts).add(gopts);
    po::options_description cfgfile_options;
    cfgfile_options.add(gopts);

    po::positional_options_description p;
    p.add("interface", -1);
    po::variables_map vm;
    try {
        po::store(po::command_line_parser(ac, av).
                  options(cmdline_options).positional(p).run(), vm);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
    po::notify(vm);

    if (config_file.size()) {
        std::ifstream ifs(config_file.c_str());
        if (!ifs) {
            std::cerr << "Could not open config file: " << config_file << "\n";
            std::exit(EXIT_FAILURE);
        }
        po::store(po::parse_config_file(ifs, cfgfile_options), vm);
        po::notify(vm);
    }

    if (vm.count("help")) {
        std::cout << "nrad6 " << NRAD6_VERSION << ", ipv6 router advertisment and dhcp server.\n"
                  << "Copyright (c) 2014 Nicholas J. Kain\n"
                  << av[0] << " [options] addresses...\n"
                  << cmdline_options << std::endl;
        std::exit(EXIT_FAILURE);
    }
    if (vm.count("version")) {
        std::cout << "nrad6 " << NRAD6_VERSION << ", ipv6 router advertisment and dhcp server.\n" <<
            "Copyright (c) 2014 Nicholas J. Kain\n"
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
            "POSSIBILITY OF SUCH DAMAGE.\n";
        std::exit(EXIT_FAILURE);
    }
    return vm;
}

std::unique_ptr<NLSocket> nl_socket;

// List of interface names for which we will act as a router.
static std::vector<std::string> router_interfaces;
static std::vector<std::unique_ptr<RA6Listener>> listeners;

static void process_options(int ac, char *av[])
{
    std::string pidfile, chroot_path;

    auto vm(fetch_options(ac, av));

    // XXX: Update
    //auto hs_secs = vm["handshake-gc-interval"].as<std::size_t>();
    //auto bindlisten_secs = vm["bindlisten-gc-interval"].as<std::size_t>();

    if (vm.count("background"))
        gflags_detach = 1;
    //if (vm.count("verbose"))
        //g_verbose_logs = true;
    if (vm.count("pidfile"))
        pidfile = vm["pidfile"].as<std::string>();
    if (vm.count("chroot"))
        chroot_path = vm["chroot"].as<std::string>();
    if (vm.count("interface"))
        router_interfaces = vm["interface"].as<std::vector<std::string>>();
    if (vm.count("user")) {
        auto t = vm["user"].as<std::string>();
        if (nk_uidgidbyname(t.c_str(), &nrad6_uid, &nrad6_gid))
            suicide("invalid user '%s' specified", t.c_str());
    }

    if (!router_interfaces.size())
        suicide("No interfaces have been specified");

    nl_socket = nk::make_unique<NLSocket>(io_service);

    for (const auto &i: router_interfaces) {
        try {
            listeners.emplace_back(nk::make_unique<RA6Listener>(io_service, i));
        } catch (const std::out_of_range &exn) {}
    }

    if (gflags_detach)
        if (daemon(0,0))
            suicide("detaching fork failed");

    if (pidfile.size() && file_exists(pidfile.c_str(), "w"))
        write_pid(pidfile.c_str());

    umask(077);
    process_signals();

    if (chroot_path.size())
        nk_set_chroot(chroot_path.c_str());
    if (nrad6_uid || nrad6_gid)
        nk_set_uidgid(nrad6_uid, nrad6_gid, NULL, 0);

    // if (enforce_seccomp())
    //     log_line("seccomp filter cannot be installed");
}

static void set_iostream_async()
{
    // Don't sync with C stdio, and don't sync cin and cout since we're not
    // interactive and are just streaming messages.
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(nullptr);
    std::cout.tie(nullptr);
}

int main(int ac, char *av[])
{
    set_iostream_async();

    gflags_log_name = const_cast<char *>("nrad6");

    process_options(ac, av);

    io_service.run();

    std::exit(EXIT_SUCCESS);
}
