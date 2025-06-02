// Hardened single-job executor: fork/exec + rlimits + Landlock + seccomp-bpf.
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "cbsandbox/json.hpp"

namespace cb {

struct Limits {
  double cpu_seconds = 2.0;                  // CPU time (user+sys)
  uint64_t wall_ms = 5000;                   // wall-clock time
  uint64_t memory_mb = 512;                  // address space (RLIMIT_AS)
  uint64_t max_output_bytes = 1u << 20;      // per stream (stdout / stderr)
  uint64_t max_file_bytes = 8u << 20;        // largest single file (RLIMIT_FSIZE)
  uint64_t max_workdir_bytes = 16u << 20;    // total bytes in the scratch dir
  uint32_t max_open_files = 64;
};

struct Policy {
  bool seccomp = true;           // syscall deny-list (network, fork, ptrace, ...)
  bool landlock = true;          // filesystem + TCP + signal confinement
  bool require_landlock = false; // fail closed when the kernel lacks Landlock
  bool allow_threads = false;    // permit clone(CLONE_THREAD)
  std::vector<std::string> extra_ro_paths;  // additional read+exec paths
};

struct Job {
  std::string id;
  std::vector<std::string> argv;  // argv[0] must be an absolute path
  std::vector<std::pair<std::string, std::string>> env;  // extra KEY=VALUE
  std::string stdin_data;
  std::vector<std::pair<std::string, std::string>> files;  // relative path -> content
  Limits limits;
  Policy policy;
};

enum class Status {
  Ok,                // exited 0
  NonZeroExit,       // exited with a non-zero code
  Timeout,           // wall-clock limit
  CpuLimit,          // CPU-time limit
  MemoryLimit,       // address-space limit (heuristic: allocation failure)
  OutputLimit,       // stdout/stderr/file/disk quota exceeded
  SandboxViolation,  // killed by seccomp (SIGSYS)
  Signaled,          // killed by some other signal
  SetupError         // sandbox could not start the program
};

const char* status_name(Status s);

struct Result {
  std::string id;
  Status status = Status::SetupError;
  int exit_code = -1;
  int term_signal = 0;
  std::string stdout_data;
  std::string stderr_data;
  bool stdout_truncated = false;
  bool stderr_truncated = false;
  uint64_t wall_ms = 0;
  uint64_t cpu_ms = 0;
  uint64_t max_rss_kb = 0;
  bool seccomp_active = false;
  bool landlock_active = false;
  std::string detail;  // human readable explanation for failures
};

struct RunnerConfig {
  std::string base_dir = "/tmp";  // where per-job scratch dirs are created
  std::vector<std::string> default_ro_paths = {"/usr",  "/lib",  "/lib64", "/lib32",
                                               "/bin",  "/sbin", "/etc"};
};

struct Features {
  int landlock_abi = -1;  // -1 = unavailable
  bool seccomp = false;
  std::string arch;
};

Features query_features();

// Runs one job to completion. Never throws for sandboxed-program failures;
// problems are reported through Result::status.
Result run_job(const Job& job, const RunnerConfig& cfg);

Job job_from_json(const Json& j);
Json result_to_json(const Result& r);
Json features_to_json(const Features& f);

}  // namespace cb
