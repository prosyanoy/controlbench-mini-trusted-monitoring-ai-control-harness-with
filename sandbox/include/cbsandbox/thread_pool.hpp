// Fixed-size thread pool plus a helper that runs a batch of sandbox jobs.
#pragma once

#include <condition_variable>
#include <cstddef>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <type_traits>
#include <vector>

#include "cbsandbox/sandbox.hpp"

namespace cb {

class ThreadPool {
 public:
  explicit ThreadPool(size_t workers);
  ~ThreadPool();
  ThreadPool(const ThreadPool&) = delete;
  ThreadPool& operator=(const ThreadPool&) = delete;

  size_t size() const { return threads_.size(); }

  template <class F>
  auto submit(F&& f) -> std::future<std::invoke_result_t<F>> {
    using R = std::invoke_result_t<F>;
    auto task = std::make_shared<std::packaged_task<R()>>(std::forward<F>(f));
    std::future<R> fut = task->get_future();
    {
      std::lock_guard<std::mutex> lock(mu_);
      if (stopping_) throw std::runtime_error("ThreadPool is stopped");
      queue_.emplace([task] { (*task)(); });
    }
    cv_.notify_one();
    return fut;
  }

 private:
  void worker_loop();

  std::vector<std::thread> threads_;
  std::queue<std::function<void()>> queue_;
  std::mutex mu_;
  std::condition_variable cv_;
  bool stopping_ = false;
};

// Runs all jobs on `workers` threads; results are returned in input order.
std::vector<Result> run_batch(const std::vector<Job>& jobs, const RunnerConfig& cfg,
                              size_t workers);

}  // namespace cb
