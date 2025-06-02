// Internal: kernel confinement primitives (seccomp-bpf, Landlock).
#pragma once

#include <linux/filter.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace cb {

// ---- seccomp ---------------------------------------------------------------
struct SeccompProgram {
  std::vector<sock_filter> insns;
  size_t pid_patch_index = 0;  // instruction whose immediate must become the child's pid
};

// Builds the deny-list filter. Everything not listed is allowed.
SeccompProgram build_seccomp_program(bool allow_threads);

// Async-signal-safe; call in the child after NO_NEW_PRIVS. Returns 0 or errno.
int install_seccomp(SeccompProgram& prog, int self_pid);

const char* seccomp_arch_name();

// ---- landlock --------------------------------------------------------------
struct LandlockRule {
  std::string path;
  uint64_t access = 0;  // already masked for file/dir and for the ABI
};

struct LandlockPlan {
  int abi = -1;
  uint64_t handled_fs = 0;
  uint64_t handled_net = 0;
  uint64_t scoped = 0;
  std::vector<LandlockRule> rules;
};

// Returns the kernel's Landlock ABI version, or -1 when unsupported/disabled.
int landlock_abi();

// Builds a plan: `workdir` is fully writable, `ro_paths` are read+exec only.
LandlockPlan build_landlock_plan(int abi, const std::string& workdir,
                                 const std::vector<std::string>& ro_paths);

// Async-signal-safe; call in the child after NO_NEW_PRIVS. Returns 0 or errno.
int apply_landlock(const LandlockPlan& plan);

}  // namespace cb
