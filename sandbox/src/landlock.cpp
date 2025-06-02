// Landlock via raw syscalls so we do not depend on recent kernel headers.
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>

#include "confine.hpp"

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#endif

namespace cb {
namespace {

constexpr uint64_t FS_EXECUTE = 1ull << 0;
constexpr uint64_t FS_WRITE_FILE = 1ull << 1;
constexpr uint64_t FS_READ_FILE = 1ull << 2;
constexpr uint64_t FS_READ_DIR = 1ull << 3;
constexpr uint64_t FS_BASE_MASK = (1ull << 13) - 1;  // ABI 1 bits 0..12
constexpr uint64_t FS_REFER = 1ull << 13;             // ABI 2
constexpr uint64_t FS_TRUNCATE = 1ull << 14;          // ABI 3
constexpr uint64_t NET_BIND_TCP = 1ull << 0;          // ABI 4
constexpr uint64_t NET_CONNECT_TCP = 1ull << 1;
constexpr uint64_t SCOPE_ABSTRACT_UNIX = 1ull << 0;   // ABI 6
constexpr uint64_t SCOPE_SIGNAL = 1ull << 1;

constexpr uint32_t CREATE_RULESET_VERSION = 1u << 0;
constexpr int RULE_PATH_BENEATH = 1;

struct RulesetAttr {
  uint64_t handled_access_fs;
  uint64_t handled_access_net;
  uint64_t scoped;
};

struct __attribute__((packed)) PathBeneathAttr {
  uint64_t allowed_access;
  int32_t parent_fd;
};

size_t attr_size_for_abi(int abi) {
  if (abi >= 6) return sizeof(RulesetAttr);
  if (abi >= 4) return 16;
  return 8;
}

}  // namespace

int landlock_abi() {
  long v = syscall(__NR_landlock_create_ruleset, nullptr, 0, CREATE_RULESET_VERSION);
  return v < 0 ? -1 : static_cast<int>(v);
}

LandlockPlan build_landlock_plan(int abi, const std::string& workdir,
                                 const std::vector<std::string>& ro_paths) {
  LandlockPlan plan;
  plan.abi = abi;
  plan.handled_fs = FS_BASE_MASK;
  if (abi >= 2) plan.handled_fs |= FS_REFER;
  if (abi >= 3) plan.handled_fs |= FS_TRUNCATE;
  if (abi >= 4) plan.handled_net = NET_BIND_TCP | NET_CONNECT_TCP;
  if (abi >= 6) plan.scoped = SCOPE_ABSTRACT_UNIX | SCOPE_SIGNAL;

  const uint64_t file_bits = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE;

  auto add = [&](const std::string& path, uint64_t access) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return;  // missing paths are simply not granted
    access &= plan.handled_fs;
    if (!S_ISDIR(st.st_mode)) access &= file_bits;
    if (access) plan.rules.push_back({path, access});
  };

  add(workdir, plan.handled_fs);  // everything inside the scratch dir
  for (const auto& p : ro_paths) add(p, FS_EXECUTE | FS_READ_FILE | FS_READ_DIR);
  add("/dev/null", FS_READ_FILE | FS_WRITE_FILE | FS_TRUNCATE);
  add("/dev/zero", FS_READ_FILE);
  add("/dev/urandom", FS_READ_FILE);
  add("/dev/random", FS_READ_FILE);
  return plan;
}

// Everything below must stay async-signal-safe (called between fork and exec).
int apply_landlock(const LandlockPlan& plan) {
  RulesetAttr attr{plan.handled_fs, plan.handled_net, plan.scoped};
  int ruleset = static_cast<int>(
      syscall(__NR_landlock_create_ruleset, &attr, attr_size_for_abi(plan.abi), 0));
  if (ruleset < 0) return errno;

  for (const auto& rule : plan.rules) {
    int fd = open(rule.path.c_str(), O_PATH | O_CLOEXEC);
    if (fd < 0) {
      if (errno == ENOENT) continue;
      int e = errno;
      close(ruleset);
      return e;
    }
    PathBeneathAttr pb{rule.access, fd};
    long rc = syscall(__NR_landlock_add_rule, ruleset, RULE_PATH_BENEATH, &pb, 0);
    int e = errno;
    close(fd);
    if (rc != 0) {
      close(ruleset);
      return e;
    }
  }

  long rc = syscall(__NR_landlock_restrict_self, ruleset, 0);
  int e = errno;
  close(ruleset);
  return rc == 0 ? 0 : e;
}

}  // namespace cb
