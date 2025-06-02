#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <stdexcept>
#include <thread>

#include "cbsandbox/thread_pool.hpp"

TEST(ThreadPool, RunsAllTasksAndReturnsValues) {
  cb::ThreadPool pool(4);
  std::vector<std::future<int>> fs;
  for (int i = 0; i < 100; ++i) fs.push_back(pool.submit([i] { return i * i; }));
  for (int i = 0; i < 100; ++i) EXPECT_EQ(fs[i].get(), i * i);
}

TEST(ThreadPool, ExecutesConcurrently) {
  cb::ThreadPool pool(4);
  std::atomic<int> running{0}, peak{0};
  std::vector<std::future<void>> fs;
  for (int i = 0; i < 8; ++i) {
    fs.push_back(pool.submit([&] {
      int now = ++running;
      int p = peak.load();
      while (now > p && !peak.compare_exchange_weak(p, now)) {}
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      --running;
    }));
  }
  for (auto& f : fs) f.get();
  EXPECT_GT(peak.load(), 1);
  EXPECT_LE(peak.load(), 4);
}

TEST(ThreadPool, PropagatesExceptions) {
  cb::ThreadPool pool(2);
  auto f = pool.submit([]() -> int { throw std::runtime_error("boom"); });
  EXPECT_THROW(f.get(), std::runtime_error);
}

TEST(ThreadPool, DestructorDrainsQueue) {
  std::atomic<int> done{0};
  {
    cb::ThreadPool pool(2);
    for (int i = 0; i < 20; ++i) pool.submit([&] { ++done; });
  }
  EXPECT_EQ(done.load(), 20);
}
