#include "cbsandbox/thread_pool.hpp"

namespace cb {

ThreadPool::ThreadPool(size_t workers) {
  if (workers == 0) workers = 1;
  for (size_t i = 0; i < workers; ++i) threads_.emplace_back([this] { worker_loop(); });
}

ThreadPool::~ThreadPool() {
  {
    std::lock_guard<std::mutex> lock(mu_);
    stopping_ = true;
  }
  cv_.notify_all();
  for (auto& t : threads_) t.join();
}

void ThreadPool::worker_loop() {
  while (true) {
    std::function<void()> task;
    {
      std::unique_lock<std::mutex> lock(mu_);
      cv_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
      if (queue_.empty()) return;  // stopping and drained
      task = std::move(queue_.front());
      queue_.pop();
    }
    task();
  }
}

std::vector<Result> run_batch(const std::vector<Job>& jobs, const RunnerConfig& cfg,
                              size_t workers) {
  ThreadPool pool(workers);
  std::vector<std::future<Result>> futures;
  futures.reserve(jobs.size());
  for (const Job& job : jobs) {
    futures.push_back(pool.submit([&job, &cfg] {
      try {
        return run_job(job, cfg);
      } catch (const std::exception& e) {
        Result r;
        r.id = job.id;
        r.status = Status::SetupError;
        r.detail = std::string("internal error: ") + e.what();
        return r;
      }
    }));
  }
  std::vector<Result> results;
  results.reserve(jobs.size());
  for (auto& f : futures) results.push_back(f.get());
  return results;
}

}  // namespace cb
