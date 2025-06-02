PY ?= .venv/bin/python
BUILD ?= build

.PHONY: setup build test test-cpp test-py run quick clean
setup:            ## create venv, install Python deps (incl. cmake + pytest from PyPI)
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"

build:            ## compile the C++ sandbox and its GoogleTest suite
	PATH="$(CURDIR)/.venv/bin:$$PATH" cmake -S sandbox -B $(BUILD) -DCMAKE_BUILD_TYPE=Release
	PATH="$(CURDIR)/.venv/bin:$$PATH" cmake --build $(BUILD) -j

test-cpp: build
	./$(BUILD)/sandbox_tests

test-py: build
	.venv/bin/pytest -q

test: test-cpp test-py

run: build          ## full sweep: results/results.csv, pareto.csv, pareto.png, ...
	.venv/bin/controlbench run

quick: build        ## fast smoke run
	.venv/bin/controlbench run --quick --out results

clean:
	rm -rf $(BUILD) results .pytest_cache
