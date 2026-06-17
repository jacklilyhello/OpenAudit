# OpenAudit Phase 12 Performance Benchmarks

## Purpose

This document records Phase 12 benchmark evidence for the current OpenAudit codebase. The goal is documentation-only: measure the existing matcher behavior, document reproducible reference results, and support conservative README performance wording without changing runtime code.

README performance wording is based on the benchmark data in this file. These results are reference measurements from one Cloud Codex run, not universal production guarantees.

## Benchmarked code state

* Benchmarked main commit: `c490cff56c167bd347750ec9f07ba60f8401a6c8`
* `HEAD` and `origin/main` were synchronized before benchmarking: `git rev-list --left-right --count HEAD...origin/main` returned `0 0`.
* Phase 13 was included in the benchmarked main history. The benchmarked history also includes later merged Phase 14 and Phase 15 work.

Recent benchmarked history:

```text
c490cff Merge pull request #15 from jacklilyhello/phase-15-review-queue-admin-workflow
bd2591c Implement Phase 15 review queue workflow
d74c2fd Merge pull request #14 from jacklilyhello/phase-14-ai-review-providers
75a21f3 Implement Phase 14 AI review providers
4414bc1 Merge pull request #13 from jacklilyhello/phase-13-variant-normalization
93978f7 Implement Phase 13 variant normalization
5ab4567 Merge pull request #12 from jacklilyhello/phase-11-rule-release-workflow
f1848de Implement Phase 11 rule release workflow
```

## Environment

* OS: Linux `6.12.47` on `x86_64`
* Architecture: `linux/amd64`
* Go version: `go1.25.0 linux/amd64`
* CPU reported by Go benchmark: `Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz`
* Available CPUs reported by `lscpu`: 3
* Environment caveat: benchmarks were run in a shared Cloud Codex container. CPU scheduling, thermal state, neighboring workloads, filesystem cache, and container limits can affect absolute timings.

## Validation and benchmark commands used

Validation commands run during this Phase 12 session:

```bash
go fmt ./...
go test ./...
go vet ./...
make ci
make test
make build
make smoke
go build ./...
go run ./cmd/server
$(go env GOPATH)/bin/gosec ./...
make docker-build
```

Benchmark commands run during this Phase 12 session:

```bash
go test -bench=. -benchmem ./...
go test -run TestPhase12LatencyAndBuild -bench='BenchmarkPhase12' -benchmem ./internal/matcher
go test -v -run TestPhase12LatencyAndBuild ./internal/matcher
```

The Phase 12 helper benchmark files were temporary `_test.go` files used only to collect measurements. They were removed before the final commit.

## Benchmark matrix

| Area | Coverage in this run |
| --- | --- |
| Keyword matcher | 10k and 100k keyword match benchmarks; 10k, 100k, and 1M build timing measurements |
| Regex matcher | 100 compiled regex rules against 1KB, 10KB, and 100KB synthetic text |
| Domain matcher | 100 domain rules against 1KB, 10KB, and 100KB synthetic text |
| Text sizes | 1KB, 10KB, and 100KB |
| Batch sizes | 100 and 1000 documents, each 1KB, using 100k keyword matcher |
| Reload/build time | Keyword matcher build measured for 10k and 100k through `testing.B`; 10k, 100k, and 1M measured through a timed helper test |
| Memory/allocation | `-benchmem` for match and build benchmarks; heap-after-GC snapshots for timed build helper |
| Latency distribution | p50/p95/p99 measured for selected keyword matcher scenarios with 1000 samples each |

Synthetic data was deterministic and generated in temporary benchmark helpers. No external datasets or network services were used for benchmark data.

## Measured results

### Keyword matcher: 10k and 100k rules

The keyword matcher used deterministic synthetic keyword rules named `tokenNNNNNN`. The text contained no configured benchmark token, so these are no-hit scan measurements.

| Rules | Text size | Iterations | ns/op | B/op | allocs/op |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 10,000 | 1KB | 77,041 | 14,597 | 4,096 | 1 |
| 10,000 | 10KB | 7,722 | 156,711 | 40,960 | 1 |
| 10,000 | 100KB | 985 | 2,080,290 | 409,600 | 1 |
| 100,000 | 1KB | 86,022 | 15,875 | 4,096 | 1 |
| 100,000 | 10KB | 10,000 | 123,918 | 40,960 | 1 |
| 100,000 | 100KB | 896 | 1,499,964 | 409,600 | 1 |

Interpretation: in this no-hit synthetic scan, keyword match time scaled primarily with input text size. Increasing the keyword set from 10k to 100k did not produce a proportional scan-time increase, which is consistent with the Aho-Corasick-style matcher design. Absolute timings remain environment-specific.

### Keyword batch scans

Batch measurements used the 100k keyword matcher and 1KB synthetic documents.

| Batch size | Iterations | ns/op | B/op | allocs/op |
| ---: | ---: | ---: | ---: | ---: |
| 100 | 1,090 | 1,300,583 | 409,600 | 100 |
| 1000 | 100 | 14,279,049 | 4,096,000 | 1000 |

Interpretation: batch runtime and allocations scaled approximately with the number of 1KB documents because each document was scanned independently.

### Regex matcher

Regex measurements used 100 compiled deterministic regex patterns and synthetic no-hit text.

| Rules | Text size | Iterations | ns/op | B/op | allocs/op |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 1KB | 29,008 | 40,093 | 2 | 0 |
| 100 | 10KB | 4,789 | 282,386 | 7 | 0 |
| 100 | 100KB | 410 | 4,949,470 | 15 | 0 |

Interpretation: regex scans were slower than keyword scans for these no-hit synthetic cases because each compiled expression is evaluated against the text. Regex performance depends strongly on pattern complexity and match density.

### Domain matcher

Domain measurements used 100 deterministic domain rules and synthetic text that included token-like neutral text but no configured matching domain.

| Rules | Text size | Iterations | ns/op | B/op | allocs/op |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 1KB | 6,398 | 191,003 | 48,910 | 30 |
| 100 | 10KB | 500 | 2,306,280 | 602,802 | 43 |
| 100 | 100KB | 55 | 23,276,545 | 7,102,443 | 63 |

Interpretation: domain matching had higher allocations and runtime in this synthetic scenario than keyword matching because it normalizes text, extracts domain-like tokens, normalizes candidate hosts, and compares against configured domain rules.

### Reload/build timing and memory

`testing.B` build measurements:

| Keyword rules | Iterations | ns/op | Approx time/op | B/op | allocs/op |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 10,000 | 9 | 119,122,097 | 119.122 ms | 19,806,329 | 278,956 |
| 100,000 | 1 | 1,434,725,856 | 1.435 s | 203,622,544 | 2,788,972 |

Timed helper build measurements with heap-after-GC snapshots:

| Keyword rules | Elapsed build time | Heap alloc after GC | Heap delta after GC |
| ---: | ---: | ---: | ---: |
| 10,000 | 212.805249 ms | 5,626,952 bytes | 5,480,128 bytes |
| 100,000 | 1.701189989 s | 55,308,456 bytes | 55,198,552 bytes |
| 1,000,000 | 18.048210537 s | 560,110,840 bytes | 560,000,856 bytes |

Interpretation: 1M keyword matcher construction was feasible in this Cloud Codex run, but it required about 18 seconds and roughly 560 MB of live heap after GC in the timed helper. The 1M case was measured for build/reload cost only; full 1M keyword scan and latency matrix measurements were not run to keep the documentation-only task bounded and avoid excessive shared-container load.

### p50 / p95 / p99 keyword latency

Latency distribution measurements used the 100k keyword matcher, deterministic no-hit synthetic text, and 1000 timed samples per text size.

| Keyword rules | Text size | Samples | p50 | p95 | p99 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100,000 | 1KB | 1000 | 9.819 µs | 17.333 µs | 24.049 µs |
| 100,000 | 10KB | 1000 | 94.863 µs | 120.09 µs | 145.582 µs |
| 100,000 | 100KB | 1000 | 1.00553 ms | 1.254344 ms | 2.393641 ms |

Interpretation: selected keyword latency measurements were low in this environment for no-hit scans. They should be treated as reference measurements only, not as production p99 guarantees.

## Caveats

* This is a shared Cloud Codex environment; benchmark values may vary across runs and machines.
* Synthetic no-hit data does not represent every production workload. Match-heavy text can allocate and return more hit records.
* Regex performance depends on pattern count, pattern complexity, and match density.
* Domain matcher measurements depend on how much domain-like text appears in the input.
* The 1M keyword case was measured for build/reload timing and heap-after-GC memory only. The full 1M keyword scan matrix was not run in this Phase 12 session.
* Temporary benchmark helpers were removed before commit, so reproduction requires recreating equivalent benchmark helpers or adding local-only benchmark files.
* No runtime code, matcher logic, audit engine logic, or API behavior was changed for these measurements.

## How to reproduce

1. Check out the benchmarked commit or a later commit you want to evaluate.
2. Confirm the repository state:

   ```bash
   git status --short
   git rev-parse HEAD
   go version
   uname -a
   lscpu
   ```

3. Run repository validation:

   ```bash
   go fmt ./...
   go test ./...
   go vet ./...
   make ci
   make test
   make build
   make smoke
   go build ./...
   ```

4. Run existing benchmarks:

   ```bash
   go test -bench=. -benchmem ./...
   ```

5. For the Phase 12 matrix, create local temporary benchmark helpers that generate deterministic synthetic keyword, regex, and domain rules; run:

   ```bash
   go test -run TestPhase12LatencyAndBuild -bench='BenchmarkPhase12' -benchmem ./internal/matcher
   go test -v -run TestPhase12LatencyAndBuild ./internal/matcher
   ```

6. Delete all temporary benchmark helper files before committing documentation.
