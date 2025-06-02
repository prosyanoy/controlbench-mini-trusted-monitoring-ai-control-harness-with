#include "cbsandbox/sandbox.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

#include "confine.hpp"

namespace cb {
namespace {

using Clock = std::chrono::steady_clock;

uint64_t ms_since(Clock::time_point t0) {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count());
}

// ----------------------------------------------------------- filesystem utils

bool safe_relative_path(const std::string& p) {
  if (p.empty() || p[0] == '/' || p.size() > 255) return false;
  size_t start = 0;
  while (start <= p.size()) {
    size_t end = p.find('/', start);
    if (end == std::string::npos) end = p.size();
    std::string part = p.substr(start, end - start);
    if (part.empty() || part == "." || part == "..") return false;
    start = end + 1;
  }
  return true;
}

bool write_file(const std::string& path, const std::string& data) {
  int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) return false;
  size_t off = 0;
  while (off < data.size()) {
    ssize_t n = write(fd, data.data() + off, data.size() - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      close(fd);
      return false;
    }
    off += static_cast<size_t>(n);
  }
  return close(fd) == 0;
}

bool make_parent_dirs(const std::string& root, const std::string& rel) {
  size_t pos = 0;
  while ((pos = rel.find('/', pos)) != std::string::npos) {
    std::string dir = root + "/" + rel.substr(0, pos);
    if (mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) return false;
    ++pos;
  }
  return true;
}

// Removes a directory tree even if the sandboxed code chmod'ed things.
void remove_tree(const std::string& path) {
  chmod(path.c_str(), 0700);
  DIR* d = opendir(path.c_str());
  if (d) {
    while (dirent* e = readdir(d)) {
      if (!std::strcmp(e->d_name, ".") || !std::strcmp(e->d_name, "..")) continue;
      std::string child = path + "/" + e->d_name;
      struct stat st;
      if (lstat(child.c_str(), &st) != 0) continue;
      if (S_ISDIR(st.st_mode)) remove_tree(child);
      else unlink(child.c_str());
    }
    closedir(d);
  }
  rmdir(path.c_str());
}

// Total bytes and entry count below `path`; stops early once over budget.
struct Usage {
  uint64_t bytes = 0;
  uint64_t entries = 0;
};
void measure_tree(const std::string& path, Usage& u, uint64_t max_entries) {
  DIR* d = opendir(path.c_str());
  if (!d) return;
  while (dirent* e = readdir(d)) {
    if (!std::strcmp(e->d_name, ".") || !std::strcmp(e->d_name, "..")) continue;
    if (++u.entries > max_entries) break;
    std::string child = path + "/" + e->d_name;
    struct stat st;
    if (lstat(child.c_str(), &st) != 0) continue;
    if (S_ISDIR(st.st_mode)) measure_tree(child, u, max_entries);
    else u.bytes += static_cast<uint64_t>(st.st_blocks) * 512;
  }
  closedir(d);
}

// CPU time (ms) of a running process from /proc/<pid>/stat; 0 if unavailable.
uint64_t proc_cpu_ms(pid_t pid) {
  std::ifstream f("/proc/" + std::to_string(pid) + "/stat");
  std::string line;
  if (!std::getline(f, line)) return 0;
  size_t rp = line.rfind(')');
  if (rp == std::string::npos) return 0;
  std::istringstream is(line.substr(rp + 2));
  std::string tok;
  unsigned long long utime = 0, stime = 0;
  for (int i = 3; i <= 15 && (is >> tok); ++i) {
    if (i == 14) utime = std::strtoull(tok.c_str(), nullptr, 10);
    if (i == 15) stime = std::strtoull(tok.c_str(), nullptr, 10);
  }
  long hz = sysconf(_SC_CLK_TCK);
  if (hz <= 0) hz = 100;
  return (utime + stime) * 1000ull / static_cast<unsigned long long>(hz);
}

// -------------------------------------------------------------- child process

struct ChildPlan {
  const char* workdir;
  char* const* argv;
  char* const* envp;
  int stdin_fd, stdout_fd, stderr_fd, err_fd;
  rlim_t cpu_soft, cpu_hard, as_bytes, fsize, nofile, nproc;
  bool use_seccomp;
  bool use_landlock;
  LandlockPlan* landlock;
  SeccompProgram* seccomp;
};

[[noreturn]] void child_fail(int err_fd, char stage, int err) {
  char buf[sizeof(int) + 1];
  buf[0] = stage;
  std::memcpy(buf + 1, &err, sizeof err);
  ssize_t ignored = write(err_fd, buf, sizeof buf);
  (void)ignored;
  _exit(127);
}

// Runs between fork() and execve(): only async-signal-safe calls, no allocation.
[[noreturn]] void child_main(const ChildPlan& p) {
  // Own session/process group so the parent can kill everything at once.
  setsid();

  struct sigaction sa;
  std::memset(&sa, 0, sizeof sa);
  sa.sa_handler = SIG_DFL;
  for (int sig : {SIGPIPE, SIGXCPU, SIGXFSZ, SIGCHLD, SIGINT, SIGTERM, SIGHUP}) sigaction(sig, &sa, nullptr);
  sigset_t all;
  sigemptyset(&all);
  sigprocmask(SIG_SETMASK, &all, nullptr);

  if (chdir(p.workdir) != 0) child_fail(p.err_fd, 'c', errno);

  if (dup2(p.stdin_fd, 0) < 0 || dup2(p.stdout_fd, 1) < 0 || dup2(p.stderr_fd, 2) < 0)
    child_fail(p.err_fd, 'd', errno);
  // Close every other descriptor except the error pipe (it is CLOEXEC).
  if (syscall(SYS_close_range, 3u, ~0u, 4u /*CLOSE_RANGE_CLOEXEC*/) != 0) {
    for (int fd = 3; fd < 1024; ++fd)
      if (fd != p.err_fd) fcntl(fd, F_SETFD, FD_CLOEXEC);
  }

  auto set = [&](int res, rlim_t soft, rlim_t hard) {
    struct rlimit rl = {soft, hard};
    return setrlimit(res, &rl) == 0;
  };
  if (!set(RLIMIT_CORE, 0, 0)) child_fail(p.err_fd, 'r', errno);
  if (!set(RLIMIT_CPU, p.cpu_soft, p.cpu_hard)) child_fail(p.err_fd, 'r', errno);
  if (!set(RLIMIT_AS, p.as_bytes, p.as_bytes)) child_fail(p.err_fd, 'r', errno);
  if (!set(RLIMIT_FSIZE, p.fsize, p.fsize)) child_fail(p.err_fd, 'r', errno);
  if (!set(RLIMIT_NOFILE, p.nofile, p.nofile)) child_fail(p.err_fd, 'r', errno);
  if (p.nproc != RLIM_INFINITY && !set(RLIMIT_NPROC, p.nproc, p.nproc)) child_fail(p.err_fd, 'r', errno);

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) child_fail(p.err_fd, 'n', errno);
  if (p.use_landlock) {
    int e = apply_landlock(*p.landlock);
    if (e) child_fail(p.err_fd, 'l', e);
  }
  if (p.use_seccomp) {
    int e = install_seccomp(*p.seccomp, static_cast<int>(getpid()));
    if (e) child_fail(p.err_fd, 's', e);
  }
  execve(p.argv[0], p.argv, p.envp);
  child_fail(p.err_fd, 'x', errno);
}

// ------------------------------------------------------------------- readers

struct Stream {
  int fd = -1;
  std::string data;
  bool truncated = false;
  uint64_t cap = 0;

  // Returns false once the stream hit EOF.
  bool pump() {
    char buf[16384];
    while (fd >= 0) {
      ssize_t n = read(fd, buf, sizeof buf);
      if (n > 0) {
        size_t room = data.size() < cap ? cap - data.size() : 0;
        size_t take = std::min<size_t>(room, static_cast<size_t>(n));
        data.append(buf, take);
        if (take < static_cast<size_t>(n)) truncated = true;
        continue;
      }
      if (n == 0) { close(fd); fd = -1; return false; }
      if (errno == EINTR) continue;
      if (errno == EAGAIN) return true;
      close(fd); fd = -1; return false;
    }
    return false;
  }
};

void set_nonblock(int fd) { fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK); }

std::string stage_name(char s) {
  switch (s) {
    case 'c': return "chdir";
    case 'd': return "dup2";
    case 'r': return "setrlimit";
    case 'n': return "no_new_privs";
    case 'l': return "landlock";
    case 's': return "seccomp";
    case 'x': return "execve";
    default: return "setup";
  }
}

}  // namespace

const char* status_name(Status s) {
  switch (s) {
    case Status::Ok: return "ok";
    case Status::NonZeroExit: return "nonzero_exit";
    case Status::Timeout: return "timeout";
    case Status::CpuLimit: return "cpu_limit";
    case Status::MemoryLimit: return "memory_limit";
    case Status::OutputLimit: return "output_limit";
    case Status::SandboxViolation: return "sandbox_violation";
    case Status::Signaled: return "signaled";
    case Status::SetupError: return "setup_error";
  }
  return "unknown";
}

Features query_features() {
  Features f;
  f.landlock_abi = landlock_abi();
  f.arch = seccomp_arch_name();
  // Probe seccomp support without affecting this process.
  const unsigned kill_process = 0x80000000u;  // SECCOMP_RET_KILL_PROCESS
  f.seccomp = syscall(__NR_seccomp, 2 /*SECCOMP_GET_ACTION_AVAIL*/, 0, &kill_process) == 0;
  return f;
}

Result run_job(const Job& job, const RunnerConfig& cfg) {
  Result res;
  res.id = job.id;
  const auto t0 = Clock::now();
  auto fail = [&](const std::string& why) {
    res.status = Status::SetupError;
    res.detail = why;
    res.wall_ms = ms_since(t0);
    return res;
  };

  if (job.argv.empty() || job.argv[0].empty() || job.argv[0][0] != '/')
    return fail("argv[0] must be an absolute path");

  // ---- scratch directory ----
  std::string templ = cfg.base_dir + "/cbs-XXXXXX";
  std::vector<char> tbuf(templ.begin(), templ.end());
  tbuf.push_back('\0');
  if (!mkdtemp(tbuf.data())) return fail(std::string("mkdtemp failed: ") + std::strerror(errno));
  const std::string workdir(tbuf.data());

  struct Cleanup {
    const std::string& dir;
    ~Cleanup() { remove_tree(dir); }
  } cleanup{workdir};

  for (const auto& f : job.files) {
    if (!safe_relative_path(f.first)) return fail("unsafe file path: " + f.first);
    if (!make_parent_dirs(workdir, f.first) || !write_file(workdir + "/" + f.first, f.second))
      return fail("could not write file " + f.first);
  }

  // ---- plans prepared before fork (no allocation after fork) ----
  std::vector<std::string> env_strs = {"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + workdir,
                                       "TMPDIR=" + workdir, "LANG=C.UTF-8",
                                       "PYTHONDONTWRITEBYTECODE=1", "PYTHONHASHSEED=0"};
  for (const auto& kv : job.env) {
    std::string entry = kv.first + "=" + kv.second;
    bool replaced = false;
    for (auto& e : env_strs)
      if (e.compare(0, kv.first.size() + 1, kv.first + "=") == 0) { e = entry; replaced = true; }
    if (!replaced) env_strs.push_back(entry);
  }
  std::vector<char*> envp;
  for (auto& s : env_strs) envp.push_back(const_cast<char*>(s.c_str()));
  envp.push_back(nullptr);
  std::vector<char*> argv;
  for (const auto& s : job.argv) argv.push_back(const_cast<char*>(s.c_str()));
  argv.push_back(nullptr);

  LandlockPlan ll_plan;
  bool use_landlock = false;
  if (job.policy.landlock) {
    int abi = landlock_abi();
    if (abi >= 1) {
      std::vector<std::string> ro = cfg.default_ro_paths;
      ro.insert(ro.end(), job.policy.extra_ro_paths.begin(), job.policy.extra_ro_paths.end());
      ll_plan = build_landlock_plan(abi, workdir, ro);
      use_landlock = true;
    } else if (job.policy.require_landlock) {
      return fail("Landlock is required but unavailable on this kernel");
    }
  }
  SeccompProgram sc_prog;
  if (job.policy.seccomp) sc_prog = build_seccomp_program(job.policy.allow_threads);

  const Limits& L = job.limits;
  const double cpu = std::max(L.cpu_seconds, 0.05);
  ChildPlan plan{};
  plan.workdir = workdir.c_str();
  plan.argv = argv.data();
  plan.envp = envp.data();
  plan.cpu_soft = static_cast<rlim_t>(std::ceil(cpu)) + 1;  // parent enforces the precise value
  plan.cpu_hard = plan.cpu_soft + 1;
  plan.as_bytes = static_cast<rlim_t>(L.memory_mb) << 20;
  plan.fsize = static_cast<rlim_t>(L.max_file_bytes);
  plan.nofile = L.max_open_files;
  plan.nproc = job.policy.allow_threads ? RLIM_INFINITY : 1;  // defence in depth vs. seccomp
  plan.use_seccomp = job.policy.seccomp;
  plan.use_landlock = use_landlock;
  plan.landlock = &ll_plan;
  plan.seccomp = &sc_prog;

  // ---- pipes ----
  int in_p[2], out_p[2], err_p[2], ctl_p[2];
  if (pipe2(in_p, O_CLOEXEC) || pipe2(out_p, O_CLOEXEC) || pipe2(err_p, O_CLOEXEC) ||
      pipe2(ctl_p, O_CLOEXEC))
    return fail(std::string("pipe2 failed: ") + std::strerror(errno));
  plan.stdin_fd = in_p[0];
  plan.stdout_fd = out_p[1];
  plan.stderr_fd = err_p[1];
  plan.err_fd = ctl_p[1];

  pid_t pid = fork();
  if (pid < 0) {
    for (int fd : {in_p[0], in_p[1], out_p[0], out_p[1], err_p[0], err_p[1], ctl_p[0], ctl_p[1]}) close(fd);
    return fail(std::string("fork failed: ") + std::strerror(errno));
  }
  if (pid == 0) child_main(plan);

  close(in_p[0]);
  close(out_p[1]);
  close(err_p[1]);
  close(ctl_p[1]);

  // Blocks until the child execs (CLOEXEC closes the pipe) or reports a failure.
  char ctl[sizeof(int) + 1];
  ssize_t got;
  do { got = read(ctl_p[0], ctl, sizeof ctl); } while (got < 0 && errno == EINTR);
  close(ctl_p[0]);
  if (got == static_cast<ssize_t>(sizeof ctl)) {
    int err;
    std::memcpy(&err, ctl + 1, sizeof err);
    int status;
    waitpid(pid, &status, 0);
    for (int fd : {in_p[1], out_p[0], err_p[0]}) close(fd);
    return fail(stage_name(ctl[0]) + " failed: " + std::strerror(err));
  }

  Stream out, err;
  out.fd = out_p[0];
  err.fd = err_p[0];
  out.cap = err.cap = L.max_output_bytes;
  set_nonblock(out.fd);
  set_nonblock(err.fd);
  int stdin_fd = in_p[1];
  size_t stdin_off = 0;
  if (job.stdin_data.empty()) {
    close(stdin_fd);
    stdin_fd = -1;
  } else {
    set_nonblock(stdin_fd);
  }

  // ---- supervise ----
  const auto deadline = t0 + std::chrono::milliseconds(L.wall_ms);
  const uint64_t cpu_limit_ms = static_cast<uint64_t>(cpu * 1000.0);
  bool timed_out = false, cpu_exceeded = false, quota_exceeded = false, exited = false;
  std::string quota_why;
  int wstatus = 0;
  struct rusage ru;
  std::memset(&ru, 0, sizeof ru);
  auto last_check = Clock::now();

  while (true) {
    pid_t w = wait4(pid, &wstatus, WNOHANG, &ru);
    if (w == pid) { exited = true; break; }

    auto now = Clock::now();
    if (now >= deadline) { timed_out = true; break; }
    if (now - last_check >= std::chrono::milliseconds(20)) {
      last_check = now;
      if (proc_cpu_ms(pid) > cpu_limit_ms) { cpu_exceeded = true; break; }
      Usage u;
      measure_tree(workdir, u, 4096);
      if (u.bytes > L.max_workdir_bytes || u.entries > 4096) {
        quota_exceeded = true;
        quota_why = "scratch directory quota exceeded";
        break;
      }
    }
    if ((out.truncated || err.truncated)) {
      quota_exceeded = true;
      quota_why = "output limit exceeded";
      break;
    }

    pollfd fds[3];
    nfds_t n = 0;
    int idx_out = -1, idx_err = -1, idx_in = -1;
    if (out.fd >= 0) { idx_out = static_cast<int>(n); fds[n++] = {out.fd, POLLIN, 0}; }
    if (err.fd >= 0) { idx_err = static_cast<int>(n); fds[n++] = {err.fd, POLLIN, 0}; }
    if (stdin_fd >= 0) { idx_in = static_cast<int>(n); fds[n++] = {stdin_fd, POLLOUT, 0}; }
    long remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
    int timeout = static_cast<int>(std::max<long>(1, std::min<long>(remaining, 5)));
    int pr = poll(fds, n, timeout);
    if (pr < 0 && errno != EINTR) break;
    if (pr > 0) {
      if (idx_out >= 0 && fds[idx_out].revents) out.pump();
      if (idx_err >= 0 && fds[idx_err].revents) err.pump();
      if (idx_in >= 0 && fds[idx_in].revents) {
        if (fds[idx_in].revents & (POLLERR | POLLHUP)) {
          close(stdin_fd);
          stdin_fd = -1;
        } else {
          ssize_t wn = write(stdin_fd, job.stdin_data.data() + stdin_off,
                             job.stdin_data.size() - stdin_off);
          if (wn > 0) stdin_off += static_cast<size_t>(wn);
          if ((wn < 0 && errno != EAGAIN && errno != EINTR) || stdin_off >= job.stdin_data.size()) {
            close(stdin_fd);
            stdin_fd = -1;
          }
        }
      }
    }
  }

  // Whatever happened, nothing from the job may outlive it.
  if (!exited) {
    kill(-pid, SIGKILL);
    kill(pid, SIGKILL);
    wait4(pid, &wstatus, 0, &ru);
  } else {
    kill(-pid, SIGKILL);  // sweep any stragglers in the process group
  }
  if (stdin_fd >= 0) close(stdin_fd);
  out.pump();
  err.pump();
  if (out.fd >= 0) close(out.fd);
  if (err.fd >= 0) close(err.fd);

  res.stdout_data = std::move(out.data);
  res.stderr_data = std::move(err.data);
  res.stdout_truncated = out.truncated;
  res.stderr_truncated = err.truncated;
  res.wall_ms = ms_since(t0);
  res.cpu_ms = static_cast<uint64_t>(ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) * 1000 +
               static_cast<uint64_t>(ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) / 1000;
  res.max_rss_kb = static_cast<uint64_t>(ru.ru_maxrss);
  res.seccomp_active = job.policy.seccomp;
  res.landlock_active = use_landlock;

  auto mentions_oom = [&] {
    return res.stderr_data.find("MemoryError") != std::string::npos ||
           res.stderr_data.find("bad_alloc") != std::string::npos ||
           res.stderr_data.find("Cannot allocate memory") != std::string::npos;
  };

  if (timed_out) {
    res.status = Status::Timeout;
    res.detail = "wall-clock limit of " + std::to_string(L.wall_ms) + " ms exceeded";
    return res;
  }
  if (cpu_exceeded) {
    res.status = Status::CpuLimit;
    res.detail = "CPU limit of " + std::to_string(cpu_limit_ms) + " ms exceeded";
    return res;
  }
  if (quota_exceeded) {
    res.status = Status::OutputLimit;
    res.detail = quota_why;
    return res;
  }
  if (WIFEXITED(wstatus)) {
    res.exit_code = WEXITSTATUS(wstatus);
    if (res.exit_code == 0) {
      res.status = Status::Ok;
    } else if (mentions_oom()) {
      res.status = Status::MemoryLimit;
      res.detail = "memory limit of " + std::to_string(L.memory_mb) + " MB exceeded";
    } else {
      res.status = Status::NonZeroExit;
    }
    return res;
  }
  res.term_signal = WTERMSIG(wstatus);
  switch (res.term_signal) {
    case SIGSYS:
      res.status = Status::SandboxViolation;
      res.detail = "blocked system call (seccomp)";
      break;
    case SIGXCPU:
      res.status = Status::CpuLimit;
      res.detail = "CPU limit exceeded";
      break;
    case SIGXFSZ:
      res.status = Status::OutputLimit;
      res.detail = "file size limit exceeded";
      break;
    default:
      if ((res.term_signal == SIGSEGV || res.term_signal == SIGABRT || res.term_signal == SIGBUS) &&
          (mentions_oom() || res.max_rss_kb * 1024 >= (L.memory_mb << 20) * 8 / 10)) {
        res.status = Status::MemoryLimit;
        res.detail = "memory limit of " + std::to_string(L.memory_mb) + " MB exceeded";
      } else {
        res.status = Status::Signaled;
        res.detail = std::string("terminated by signal ") + strsignal(res.term_signal);
      }
  }
  return res;
}

// ---------------------------------------------------------------- JSON codec

Job job_from_json(const Json& j) {
  if (!j.is_object()) throw JsonError("job must be an object");
  Job job;
  if (auto* v = j.find("id")) job.id = v->is_string() ? v->as_string() : v->dump();
  const Json* argv = j.find("argv");
  if (!argv || !argv->is_array()) throw JsonError("job.argv must be an array");
  for (const auto& a : argv->as_array()) job.argv.push_back(a.as_string());
  if (auto* v = j.find("stdin")) job.stdin_data = v->as_string();
  if (auto* v = j.find("env"))
    for (const auto& m : v->as_object()) job.env.emplace_back(m.first, m.second.as_string());
  if (auto* v = j.find("files"))
    for (const auto& m : v->as_object()) job.files.emplace_back(m.first, m.second.as_string());
  if (auto* v = j.find("limits")) {
    Limits& l = job.limits;
    if (auto* x = v->find("cpu_seconds")) l.cpu_seconds = x->as_double();
    if (auto* x = v->find("wall_ms")) l.wall_ms = static_cast<uint64_t>(x->as_int());
    if (auto* x = v->find("memory_mb")) l.memory_mb = static_cast<uint64_t>(x->as_int());
    if (auto* x = v->find("max_output_bytes")) l.max_output_bytes = static_cast<uint64_t>(x->as_int());
    if (auto* x = v->find("max_file_bytes")) l.max_file_bytes = static_cast<uint64_t>(x->as_int());
    if (auto* x = v->find("max_workdir_bytes")) l.max_workdir_bytes = static_cast<uint64_t>(x->as_int());
    if (auto* x = v->find("max_open_files")) l.max_open_files = static_cast<uint32_t>(x->as_int());
  }
  if (auto* v = j.find("policy")) {
    Policy& p = job.policy;
    if (auto* x = v->find("seccomp")) p.seccomp = x->as_bool();
    if (auto* x = v->find("landlock")) p.landlock = x->as_bool();
    if (auto* x = v->find("require_landlock")) p.require_landlock = x->as_bool();
    if (auto* x = v->find("allow_threads")) p.allow_threads = x->as_bool();
    if (auto* x = v->find("extra_ro_paths"))
      for (const auto& s : x->as_array()) p.extra_ro_paths.push_back(s.as_string());
  }
  return job;
}

Json result_to_json(const Result& r) {
  Json o = Json::object();
  o.set("id", r.id);
  o.set("status", status_name(r.status));
  o.set("exit_code", r.exit_code);
  o.set("signal", r.term_signal);
  o.set("stdout", r.stdout_data);
  o.set("stderr", r.stderr_data);
  o.set("stdout_truncated", r.stdout_truncated);
  o.set("stderr_truncated", r.stderr_truncated);
  o.set("wall_ms", r.wall_ms);
  o.set("cpu_ms", r.cpu_ms);
  o.set("max_rss_kb", r.max_rss_kb);
  o.set("seccomp", r.seccomp_active);
  o.set("landlock", r.landlock_active);
  o.set("detail", r.detail);
  return o;
}

Json features_to_json(const Features& f) {
  Json o = Json::object();
  o.set("landlock_abi", f.landlock_abi);
  o.set("seccomp", f.seccomp);
  o.set("arch", f.arch);
  return o;
}

}  // namespace cb
