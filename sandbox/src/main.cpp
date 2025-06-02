// cb_sandbox: reads a JSON batch of jobs on stdin, runs them on a thread pool,
// writes a JSON array of results (same order) on stdout.
#include <signal.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <iterator>
#include <thread>

#include "cbsandbox/sandbox.hpp"
#include "cbsandbox/thread_pool.hpp"

namespace {

void usage() {
  std::fputs(
      "usage: cb_sandbox [--workers N] [--base-dir DIR] [--ro-path PATH]... [--features]\n"
      "  Reads {\"jobs\":[...]} (or a bare array) from stdin and prints a JSON array of results.\n"
      "  --features  print detected kernel features as JSON and exit\n",
      stderr);
}

}  // namespace

int main(int argc, char** argv) {
  size_t workers = std::max(1u, std::thread::hardware_concurrency());
  cb::RunnerConfig cfg;
  bool features_only = false;

  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    auto need = [&](const char* name) -> const char* {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "missing value for %s\n", name);
        std::exit(2);
      }
      return argv[++i];
    };
    if (a == "--workers") workers = static_cast<size_t>(std::max(1, std::atoi(need("--workers"))));
    else if (a == "--base-dir") cfg.base_dir = need("--base-dir");
    else if (a == "--ro-path") cfg.default_ro_paths.push_back(need("--ro-path"));
    else if (a == "--features") features_only = true;
    else if (a == "--help" || a == "-h") { usage(); return 0; }
    else { usage(); return 2; }
  }

  // A job closing its stdin early must not kill the supervisor.
  signal(SIGPIPE, SIG_IGN);

  if (features_only) {
    std::puts(cb::features_to_json(cb::query_features()).dump().c_str());
    return 0;
  }

  try {
    std::string input((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
    cb::Json doc = cb::Json::parse(input);
    const cb::Json* list = &doc;
    if (doc.is_object()) {
      list = doc.find("jobs");
      if (!list) throw cb::JsonError("missing \"jobs\"");
    }
    std::vector<cb::Job> jobs;
    for (const auto& j : list->as_array()) jobs.push_back(cb::job_from_json(j));

    auto results = cb::run_batch(jobs, cfg, workers);
    cb::Json out = cb::Json::array();
    for (const auto& r : results) out.push(cb::result_to_json(r));
    std::string text = out.dump();
    text.push_back('\n');
    std::fwrite(text.data(), 1, text.size(), stdout);
    return 0;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "cb_sandbox: %s\n", e.what());
    return 2;
  }
}
