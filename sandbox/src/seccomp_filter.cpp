#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>

#include "confine.hpp"

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif

#if defined(__x86_64__)
#define CB_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define CB_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "ControlBench sandbox supports x86_64 and aarch64 only"
#endif

namespace cb {

const char* seccomp_arch_name() {
#if defined(__x86_64__)
  return "x86_64";
#else
  return "aarch64";
#endif
}

namespace {

constexpr uint32_t kOffNr = offsetof(struct seccomp_data, nr);
constexpr uint32_t kOffArch = offsetof(struct seccomp_data, arch);
constexpr uint32_t kOffArg0 = offsetof(struct seccomp_data, args[0]);  // little endian: low word

// Syscalls that terminate the process (SIGSYS) when invoked.
std::vector<uint32_t> denied_syscalls() {
  std::vector<uint32_t> nrs;
#define DENY(name) nrs.push_back(static_cast<uint32_t>(name))
  // Network: no sockets of any family, so nothing can leave the box.
#ifdef __NR_socket
  DENY(__NR_socket);
#endif
#ifdef __NR_socketpair
  DENY(__NR_socketpair);
#endif
#ifdef __NR_connect
  DENY(__NR_connect);
#endif
#ifdef __NR_bind
  DENY(__NR_bind);
#endif
#ifdef __NR_listen
  DENY(__NR_listen);
#endif
#ifdef __NR_accept
  DENY(__NR_accept);
#endif
#ifdef __NR_accept4
  DENY(__NR_accept4);
#endif
  // io_uring can perform network and file operations outside seccomp's view.
#ifdef __NR_io_uring_setup
  DENY(__NR_io_uring_setup);
#endif
#ifdef __NR_io_uring_enter
  DENY(__NR_io_uring_enter);
#endif
#ifdef __NR_io_uring_register
  DENY(__NR_io_uring_register);
#endif
  // Process creation (fork bombs). clone() is handled separately.
#ifdef __NR_fork
  DENY(__NR_fork);
#endif
#ifdef __NR_vfork
  DENY(__NR_vfork);
#endif
  // Inspecting or signalling other processes.
#ifdef __NR_ptrace
  DENY(__NR_ptrace);
#endif
#ifdef __NR_process_vm_readv
  DENY(__NR_process_vm_readv);
#endif
#ifdef __NR_process_vm_writev
  DENY(__NR_process_vm_writev);
#endif
#ifdef __NR_kill
  DENY(__NR_kill);
#endif
#ifdef __NR_tkill
  DENY(__NR_tkill);
#endif
#ifdef __NR_rt_sigqueueinfo
  DENY(__NR_rt_sigqueueinfo);
#endif
#ifdef __NR_rt_tgsigqueueinfo
  DENY(__NR_rt_tgsigqueueinfo);
#endif
#ifdef __NR_pidfd_open
  DENY(__NR_pidfd_open);
#endif
#ifdef __NR_pidfd_send_signal
  DENY(__NR_pidfd_send_signal);
#endif
#ifdef __NR_pidfd_getfd
  DENY(__NR_pidfd_getfd);
#endif
  // Filesystem / namespace / privileged administration.
#ifdef __NR_mount
  DENY(__NR_mount);
#endif
#ifdef __NR_umount2
  DENY(__NR_umount2);
#endif
#ifdef __NR_umount
  DENY(__NR_umount);
#endif
#ifdef __NR_pivot_root
  DENY(__NR_pivot_root);
#endif
#ifdef __NR_chroot
  DENY(__NR_chroot);
#endif
#ifdef __NR_move_mount
  DENY(__NR_move_mount);
#endif
#ifdef __NR_open_tree
  DENY(__NR_open_tree);
#endif
#ifdef __NR_fsopen
  DENY(__NR_fsopen);
#endif
#ifdef __NR_fsconfig
  DENY(__NR_fsconfig);
#endif
#ifdef __NR_fsmount
  DENY(__NR_fsmount);
#endif
#ifdef __NR_fspick
  DENY(__NR_fspick);
#endif
#ifdef __NR_mount_setattr
  DENY(__NR_mount_setattr);
#endif
#ifdef __NR_name_to_handle_at
  DENY(__NR_name_to_handle_at);
#endif
#ifdef __NR_open_by_handle_at
  DENY(__NR_open_by_handle_at);
#endif
#ifdef __NR_unshare
  DENY(__NR_unshare);
#endif
#ifdef __NR_setns
  DENY(__NR_setns);
#endif
#ifdef __NR_swapon
  DENY(__NR_swapon);
#endif
#ifdef __NR_swapoff
  DENY(__NR_swapoff);
#endif
#ifdef __NR_reboot
  DENY(__NR_reboot);
#endif
#ifdef __NR_kexec_load
  DENY(__NR_kexec_load);
#endif
#ifdef __NR_kexec_file_load
  DENY(__NR_kexec_file_load);
#endif
#ifdef __NR_init_module
  DENY(__NR_init_module);
#endif
#ifdef __NR_finit_module
  DENY(__NR_finit_module);
#endif
#ifdef __NR_delete_module
  DENY(__NR_delete_module);
#endif
#ifdef __NR_bpf
  DENY(__NR_bpf);
#endif
#ifdef __NR_perf_event_open
  DENY(__NR_perf_event_open);
#endif
#ifdef __NR_userfaultfd
  DENY(__NR_userfaultfd);
#endif
#ifdef __NR_keyctl
  DENY(__NR_keyctl);
#endif
#ifdef __NR_add_key
  DENY(__NR_add_key);
#endif
#ifdef __NR_request_key
  DENY(__NR_request_key);
#endif
#ifdef __NR_iopl
  DENY(__NR_iopl);
#endif
#ifdef __NR_ioperm
  DENY(__NR_ioperm);
#endif
#ifdef __NR_acct
  DENY(__NR_acct);
#endif
#ifdef __NR_settimeofday
  DENY(__NR_settimeofday);
#endif
#ifdef __NR_clock_settime
  DENY(__NR_clock_settime);
#endif
#ifdef __NR_clock_adjtime
  DENY(__NR_clock_adjtime);
#endif
#ifdef __NR_adjtimex
  DENY(__NR_adjtimex);
#endif
#ifdef __NR_sethostname
  DENY(__NR_sethostname);
#endif
#ifdef __NR_setdomainname
  DENY(__NR_setdomainname);
#endif
#ifdef __NR_quotactl
  DENY(__NR_quotactl);
#endif
#ifdef __NR_personality
  DENY(__NR_personality);
#endif
#undef DENY
  return nrs;
}

sock_filter stmt(uint16_t code, uint32_t k) { return BPF_STMT(code, k); }
sock_filter jump(uint16_t code, uint32_t k, uint8_t jt, uint8_t jf) {
  return BPF_JUMP(code, k, jt, jf);
}

}  // namespace

SeccompProgram build_seccomp_program(bool allow_threads) {
  SeccompProgram p;
  auto& v = p.insns;
  const uint32_t KILL = SECCOMP_RET_KILL_PROCESS;

  // Reject foreign architectures (32-bit compat syscalls could dodge the list).
  v.push_back(stmt(BPF_LD | BPF_W | BPF_ABS, kOffArch));
  v.push_back(jump(BPF_JMP | BPF_JEQ | BPF_K, CB_AUDIT_ARCH, 1, 0));
  v.push_back(stmt(BPF_RET | BPF_K, KILL));
  v.push_back(stmt(BPF_LD | BPF_W | BPF_ABS, kOffNr));
#if defined(__x86_64__)
  // x32 ABI syscalls carry bit 30.
  v.push_back(jump(BPF_JMP | BPF_JSET | BPF_K, 0x40000000u, 0, 1));
  v.push_back(stmt(BPF_RET | BPF_K, KILL));
#endif

  for (uint32_t nr : denied_syscalls()) {
    v.push_back(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
    v.push_back(stmt(BPF_RET | BPF_K, KILL));
  }

  // clone3 takes its flags through a user pointer that BPF cannot inspect:
  // report ENOSYS so libc falls back to clone(), which we can filter.
#ifdef __NR_clone3
  v.push_back(jump(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1));
  v.push_back(stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS));
#endif

  // clone: only thread creation (CLONE_THREAD), and only when permitted.
  v.push_back(jump(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 5));
  if (allow_threads) {
    v.push_back(stmt(BPF_LD | BPF_W | BPF_ABS, kOffArg0));
    v.push_back(jump(BPF_JMP | BPF_JSET | BPF_K, CLONE_THREAD, 1, 0));
    v.push_back(stmt(BPF_RET | BPF_K, KILL));
    v.push_back(stmt(BPF_LD | BPF_W | BPF_ABS, kOffNr));
    v.push_back(stmt(BPF_LD | BPF_W | BPF_ABS, kOffNr));  // keep block length fixed
  } else {
    v.push_back(stmt(BPF_RET | BPF_K, KILL));
    v.push_back(stmt(BPF_RET | BPF_K, KILL));
    v.push_back(stmt(BPF_RET | BPF_K, KILL));
    v.push_back(stmt(BPF_RET | BPF_K, KILL));
    v.push_back(stmt(BPF_RET | BPF_K, KILL));
  }

  // tgkill: only to our own thread group (the pid is patched in the child).
#ifdef __NR_tgkill
  v.push_back(jump(BPF_JMP | BPF_JEQ | BPF_K, __NR_tgkill, 0, 4));
  v.push_back(stmt(BPF_LD | BPF_W | BPF_ABS, kOffArg0));
  p.pid_patch_index = v.size();
  v.push_back(jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0));
  v.push_back(stmt(BPF_RET | BPF_K, KILL));
  v.push_back(stmt(BPF_LD | BPF_W | BPF_ABS, kOffNr));
#endif

  v.push_back(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
  return p;
}

int install_seccomp(SeccompProgram& prog, int self_pid) {
  if (prog.pid_patch_index != 0) prog.insns[prog.pid_patch_index].k = static_cast<uint32_t>(self_pid);
  sock_fprog fprog;
  fprog.len = static_cast<unsigned short>(prog.insns.size());
  fprog.filter = prog.insns.data();
  if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &fprog) != 0) return errno;
  return 0;
}

}  // namespace cb
