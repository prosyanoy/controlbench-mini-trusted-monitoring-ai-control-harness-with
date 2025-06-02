// Integration tests: every test really forks and execs inside the sandbox.
#include <gtest/gtest.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

#include "cbsandbox/sandbox.hpp"
#include "cbsandbox/thread_pool.hpp"

namespace {

std::string python_path() {
  const char* env = std::getenv("CB_TEST_PYTHON");
  std::string p = env ? env : "/usr/bin/python3";
  char buf[4096];
  if (realpath(p.c_str(), buf)) return buf;
  return p;
}

bool have_python() { return access(python_path().c_str(), X_OK) == 0; }

// Fresh scratch base directory per test fixture instance.
class SandboxTest : public ::testing::Test {
 protected:
  void SetUp() override {
    char templ[] = "/tmp/cbtest-XXXXXX";
    ASSERT_NE(mkdtemp(templ), nullptr);
    base_ = templ;
    cfg_.base_dir = base_;
    // The secret lives in the *parent* of the per-job scratch dirs.
    secret_path_ = base_ + "/secret.txt";
    std::ofstream(secret_path_) << "TOP-SECRET-VALUE";
  }
  void TearDown() override {
    std::string cmd = "rm -rf '" + base_ + "'";
    int rc = std::system(cmd.c_str());
    (void)rc;
  }

  cb::Job py(const std::string& code) {
    cb::Job j;
    j.id = "t";
    j.argv = {python_path(), "-I", "-S", "-B", "main.py"};
    j.files = {{"main.py", code}};
    j.limits.wall_ms = 8000;
    j.limits.cpu_seconds = 4;
    return j;
  }
  cb::Job prog(std::vector<std::string> argv) {
    cb::Job j;
    j.id = "t";
    j.argv = std::move(argv);
    j.limits.wall_ms = 8000;
    return j;
  }
  cb::Result run(const cb::Job& j) { return cb::run_job(j, cfg_); }

  size_t leftover_dirs() {
    size_t n = 0;
    DIR* d = opendir(base_.c_str());
    while (dirent* e = readdir(d))
      if (!std::strncmp(e->d_name, "cbs-", 4)) ++n;
    closedir(d);
    return n;
  }

  static bool process_with_cmdline_exists(const std::string& needle) {
    DIR* d = opendir("/proc");
    bool found = false;
    while (dirent* e = readdir(d)) {
      if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
      std::ifstream f(std::string("/proc/") + e->d_name + "/cmdline");
      std::stringstream ss;
      ss << f.rdbuf();
      if (ss.str().find(needle) != std::string::npos) found = true;
    }
    closedir(d);
    return found;
  }

  std::string base_, secret_path_;
  cb::RunnerConfig cfg_;
};

}  // namespace

// ------------------------------------------------------------ basic behaviour

TEST_F(SandboxTest, CapturesStdoutStderrAndExitCode) {
  auto r = run(prog({"/bin/sh", "-c", "echo hello; echo oops >&2; exit 3"}));
  EXPECT_EQ(r.status, cb::Status::NonZeroExit) << r.detail;
  EXPECT_EQ(r.exit_code, 3);
  EXPECT_EQ(r.stdout_data, "hello\n");
  EXPECT_EQ(r.stderr_data, "oops\n");
}

TEST_F(SandboxTest, SuccessfulRunIsOk) {
  auto r = run(prog({"/bin/true"}));
  EXPECT_EQ(r.status, cb::Status::Ok) << r.detail;
  EXPECT_TRUE(r.seccomp_active);
}

TEST_F(SandboxTest, StdinIsDeliveredEvenWhenLarge) {
  cb::Job j = prog({"/bin/cat"});
  j.stdin_data.assign(600000, 'x');
  auto r = run(j);
  EXPECT_EQ(r.status, cb::Status::Ok) << r.detail;
  EXPECT_EQ(r.stdout_data.size(), 600000u);
}

TEST_F(SandboxTest, FilesAreMaterialisedInWorkdirAndCleanedUp) {
  cb::Job j = prog({"/bin/cat", "sub/a.txt"});
  j.files = {{"sub/a.txt", "payload"}};
  auto r = run(j);
  EXPECT_EQ(r.status, cb::Status::Ok) << r.detail;
  EXPECT_EQ(r.stdout_data, "payload");
  EXPECT_EQ(leftover_dirs(), 0u);
}

TEST_F(SandboxTest, RejectsPathTraversalInFiles) {
  cb::Job j = prog({"/bin/true"});
  j.files = {{"../evil", "x"}};
  EXPECT_EQ(run(j).status, cb::Status::SetupError);
  j.files = {{"/abs", "x"}};
  EXPECT_EQ(run(j).status, cb::Status::SetupError);
}

TEST_F(SandboxTest, MissingBinaryAndRelativeArgv0AreSetupErrors) {
  auto r = run(prog({"/nonexistent/bin"}));
  EXPECT_EQ(r.status, cb::Status::SetupError);
  EXPECT_NE(r.detail.find("execve"), std::string::npos) << r.detail;
  EXPECT_EQ(run(prog({"true"})).status, cb::Status::SetupError);
}

TEST_F(SandboxTest, EnvironmentIsScrubbed) {
  setenv("CB_HOST_SECRET", "leak-me", 1);
  auto r = run(prog({"/usr/bin/env"}));
  EXPECT_EQ(r.status, cb::Status::Ok) << r.detail;
  EXPECT_EQ(r.stdout_data.find("leak-me"), std::string::npos);
  EXPECT_NE(r.stdout_data.find("HOME="), std::string::npos);
}

// ------------------------------------------------------------------- limits

TEST_F(SandboxTest, WallClockLimitKillsSleepers) {
  cb::Job j = prog({"/bin/sleep", "30"});
  j.limits.wall_ms = 300;
  auto t0 = std::chrono::steady_clock::now();
  auto r = run(j);
  auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  EXPECT_EQ(r.status, cb::Status::Timeout);
  EXPECT_LT(elapsed, 3.0);
}

TEST_F(SandboxTest, CpuLimitStopsBusyLoop) {
  if (!have_python()) GTEST_SKIP();
  cb::Job j = py("while True:\n    pass\n");
  j.limits.cpu_seconds = 0.4;
  j.limits.wall_ms = 10000;
  auto r = run(j);
  EXPECT_EQ(r.status, cb::Status::CpuLimit) << r.detail;
  EXPECT_LT(r.wall_ms, 5000u);
}

TEST_F(SandboxTest, MemoryLimitStopsHugeAllocation) {
  if (!have_python()) GTEST_SKIP();
  cb::Job j = py("x = bytearray(900 * 1024 * 1024)\nprint('allocated')\n");
  j.limits.memory_mb = 256;
  auto r = run(j);
  EXPECT_EQ(r.status, cb::Status::MemoryLimit) << r.detail << r.stderr_data;
  EXPECT_EQ(r.stdout_data.find("allocated"), std::string::npos);
}

TEST_F(SandboxTest, OutputFloodIsCutOff) {
  cb::Job j = prog({"/usr/bin/yes"});
  j.limits.max_output_bytes = 64 * 1024;
  auto r = run(j);
  EXPECT_EQ(r.status, cb::Status::OutputLimit) << r.detail;
  EXPECT_TRUE(r.stdout_truncated);
  EXPECT_LE(r.stdout_data.size(), 64u * 1024);
}

TEST_F(SandboxTest, DiskFillIsStopped) {
  if (!have_python()) GTEST_SKIP();
  cb::Job j = py(
      "import time\n"
      "for i in range(100):\n"
      "    open('f%d' % i, 'wb').write(b'0' * 3000000)\n"
      "    time.sleep(0.05)\n");
  j.limits.max_workdir_bytes = 8u << 20;
  auto r = run(j);
  EXPECT_EQ(r.status, cb::Status::OutputLimit) << r.detail;
  EXPECT_EQ(leftover_dirs(), 0u);
}

// ------------------------------------------------------- escapes and bombs

TEST_F(SandboxTest, PythonForkBombIsContained) {
  if (!have_python()) GTEST_SKIP();
  auto r = run(py("import os\nwhile True:\n    os.fork()\n"));
  EXPECT_EQ(r.status, cb::Status::SandboxViolation) << r.detail;
  EXPECT_EQ(r.term_signal, SIGSYS);
}

TEST_F(SandboxTest, ShellForkBombLeavesNoProcessesBehind) {
  const std::string marker = "7654.3210";
  cb::Job j = prog({"/bin/sh", "-c",
                    "while true; do /bin/sleep " + marker + " & done"});
  j.limits.wall_ms = 1500;
  auto r = run(j);
  EXPECT_NE(r.status, cb::Status::Ok);
  EXPECT_NE(r.status, cb::Status::SetupError) << r.detail;
  usleep(200 * 1000);
  EXPECT_FALSE(process_with_cmdline_exists(marker));
}

TEST_F(SandboxTest, RlimitNprocStopsForksEvenWithoutSeccomp) {
  if (geteuid() == 0) GTEST_SKIP() << "RLIMIT_NPROC is not enforced for root";
  cb::Job j = prog({"/bin/sh", "-c", "/bin/true; echo survived"});
  j.policy.seccomp = false;
  auto r = run(j);
  EXPECT_FALSE(r.seccomp_active);
  EXPECT_EQ(r.stdout_data.find("survived"), std::string::npos) << r.stderr_data;
  EXPECT_NE(r.status, cb::Status::Ok);
}

TEST_F(SandboxTest, SubprocessIsBlocked) {
  if (!have_python()) GTEST_SKIP();
  auto r = run(py("import subprocess\nsubprocess.run(['/bin/echo', 'x'])\nprint('ran')\n"));
  EXPECT_EQ(r.status, cb::Status::SandboxViolation) << r.detail << r.stderr_data;
  EXPECT_EQ(r.stdout_data.find("ran"), std::string::npos);
}

TEST_F(SandboxTest, ThreadsBlockedByDefaultButAllowedOnRequest) {
  if (!have_python()) GTEST_SKIP();
  const char* code =
      "import threading\n"
      "out = []\n"
      "t = threading.Thread(target=lambda: out.append(1))\n"
      "t.start(); t.join()\n"
      "print(out)\n";
  EXPECT_EQ(run(py(code)).status, cb::Status::SandboxViolation);
  cb::Job j = py(code);
  j.policy.allow_threads = true;
  auto r = run(j);
  EXPECT_EQ(r.status, cb::Status::Ok) << r.detail << r.stderr_data;
  EXPECT_EQ(r.stdout_data, "[1]\n");
}

TEST_F(SandboxTest, NetworkIsUnavailable) {
  if (!have_python()) GTEST_SKIP();
  auto r = run(py("import socket\ns = socket.socket()\nprint('socket created')\n"));
  EXPECT_EQ(r.status, cb::Status::SandboxViolation) << r.detail;
  EXPECT_EQ(r.stdout_data, "");
  r = run(py("import socket\nsocket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"));
  EXPECT_EQ(r.status, cb::Status::SandboxViolation);
}

TEST_F(SandboxTest, CannotSignalOrTraceOtherProcesses) {
  if (!have_python()) GTEST_SKIP();
  auto r = run(py("import os\nos.kill(os.getppid(), 0)\nprint('signalled')\n"));
  EXPECT_EQ(r.status, cb::Status::SandboxViolation) << r.detail;
  r = run(py("import ctypes\nlibc = ctypes.CDLL(None)\nlibc.ptrace(0, 0, 0, 0)\nprint('traced')\n"));
  EXPECT_EQ(r.status, cb::Status::SandboxViolation);
}

TEST_F(SandboxTest, PrivilegedSyscallsAreBlocked) {
  if (!have_python()) GTEST_SKIP();
  for (const char* call : {"libc.chroot(b'/tmp')", "libc.mount(b'x', b'/tmp', b'tmpfs', 0, None)",
                           "libc.unshare(0x10000000)", "libc.reboot(0)"}) {
    auto r = run(py(std::string("import ctypes\nlibc = ctypes.CDLL(None)\n") + call +
                    "\nprint('escaped')\n"));
    EXPECT_EQ(r.status, cb::Status::SandboxViolation) << call << " " << r.detail;
  }
}

TEST_F(SandboxTest, CannotWriteOutsideScratchDir) {
  if (cb::query_features().landlock_abi < 1) GTEST_SKIP() << "Landlock unavailable";
  if (!have_python()) GTEST_SKIP();
  std::string target = base_ + "/pwned.txt";
  auto r = run(py("try:\n    open(" + std::string("'") + target +
                  "', 'w').write('x')\n    print('wrote')\nexcept OSError as e:\n    print('denied', e.errno)\n"));
  EXPECT_EQ(r.status, cb::Status::Ok) << r.detail << r.stderr_data;
  EXPECT_NE(r.stdout_data.find("denied"), std::string::npos) << r.stdout_data;
  EXPECT_NE(access(target.c_str(), F_OK), 0);
}

TEST_F(SandboxTest, CannotReadSecretsOutsideAllowList) {
  if (cb::query_features().landlock_abi < 1) GTEST_SKIP() << "Landlock unavailable";
  if (!have_python()) GTEST_SKIP();
  auto r = run(py("try:\n    print(open('" + secret_path_ +
                  "').read())\nexcept OSError as e:\n    print('denied')\n"));
  EXPECT_EQ(r.status, cb::Status::Ok) << r.detail << r.stderr_data;
  EXPECT_EQ(r.stdout_data.find("TOP-SECRET"), std::string::npos);
  EXPECT_NE(r.stdout_data.find("denied"), std::string::npos);
}

TEST_F(SandboxTest, RequireLandlockFailsClosedOnlyWhenUnavailable) {
  cb::Job j = prog({"/bin/true"});
  j.policy.require_landlock = true;
  auto r = run(j);
  if (cb::query_features().landlock_abi >= 1) EXPECT_EQ(r.status, cb::Status::Ok) << r.detail;
  else EXPECT_EQ(r.status, cb::Status::SetupError);
}

// --------------------------------------------------------------- batch / pool

TEST_F(SandboxTest, BatchRunsInParallelAndKeepsOrder) {
  std::vector<cb::Job> jobs;
  for (int i = 0; i < 8; ++i) {
    cb::Job j = prog({"/bin/sh", "-c", "/bin/sleep 0.3"});
    j.argv = {"/bin/sleep", "0.3"};
    j.id = "job" + std::to_string(i);
    jobs.push_back(j);
  }
  auto t0 = std::chrono::steady_clock::now();
  auto results = cb::run_batch(jobs, cfg_, 4);
  double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  ASSERT_EQ(results.size(), 8u);
  for (int i = 0; i < 8; ++i) {
    EXPECT_EQ(results[i].id, "job" + std::to_string(i));
    EXPECT_EQ(results[i].status, cb::Status::Ok) << results[i].detail;
  }
  EXPECT_LT(elapsed, 1.9);  // serial execution would take >= 2.4 s
}

TEST_F(SandboxTest, JobJsonRoundTrip) {
  cb::Json doc = cb::Json::parse(
      R"({"id":"x","argv":["/bin/echo","hi"],"stdin":"in","env":{"A":"b"},)"
      R"("files":{"f.txt":"c"},"limits":{"cpu_seconds":1.5,"wall_ms":1234,"memory_mb":64},)"
      R"("policy":{"seccomp":false,"allow_threads":true,"extra_ro_paths":["/opt"]}})");
  cb::Job j = cb::job_from_json(doc);
  EXPECT_EQ(j.id, "x");
  EXPECT_EQ(j.argv.size(), 2u);
  EXPECT_DOUBLE_EQ(j.limits.cpu_seconds, 1.5);
  EXPECT_EQ(j.limits.wall_ms, 1234u);
  EXPECT_EQ(j.limits.memory_mb, 64u);
  EXPECT_FALSE(j.policy.seccomp);
  EXPECT_TRUE(j.policy.allow_threads);
  ASSERT_EQ(j.policy.extra_ro_paths.size(), 1u);
  auto r = run(j);
  cb::Json out = cb::result_to_json(r);
  EXPECT_EQ(out.find("id")->as_string(), "x");
  EXPECT_EQ(out.find("status")->as_string(), "ok");
}
