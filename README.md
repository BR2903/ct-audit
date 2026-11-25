# ct-audit — Do Post-Quantum Libraries Survive the Compiler?

A binary-level constant-time audit of four ML-KEM (FIPS 203) implementations, compiled with 12 compilers and up to 14 optimization flag combinations.

**Authors:** Bryan Amaya, Christopher Ortiz — School of Mathematical and Computational Sciences, Yachay Tech University, Ecuador. Developed as the research project of the Cryptography course (2026).

---

## Summary

Constant-time code avoids branches and memory accesses that depend on secrets, usually with bit-mask idioms in C. Those idioms only protect the program if the compiler preserves them. This project compiles the **decapsulation** of four ML-KEM implementations with Clang 15–22 and GCC 11–14, analyzes every binary with Valgrind (ctgrind technique) for secret-dependent branches and memory accesses, and confirms selected findings with the dudect timing test on real hardware.

**3,352 configurations analyzed.** Main results:

- The **current versions** of the four implementations showed **no leaks** in any valid configuration.
- That robustness depends on **value barriers** (an empty inline-assembly statement that hides a value from the optimizer). Removing them in temporary copies of the code reproduces leaks:
  - pq-crystals and PQClean: 48/48 configurations leak with Clang 15–22 and `-Os/-Oz -flto`.
  - OpenSSL 3.5.9: leaks even at the default `-O2` with Clang 16 and later (102/216 configurations), without link-time optimization.
- **Separate source files are not a defense:** link-time optimization (`-flto`) removes that protection.
- **GCC never introduced a leak**; Clang did, more aggressively in newer versions. The transformation behind CVE-2024-37880 is still present in every Clang from 15 to 22.
- **Detectable is not the same as measurable:** on an AMD Ryzen 5 7535HS, the leak produced a measurable timing difference in pq-crystals, but the same instruction pattern was not measurable in PQClean or OpenSSL.

## Note on the `standard` branch of pq-crystals

The only audited code that leaks **as published** is the `standard` branch of `pq-crystals/kyber` (commit `d5b791c`), a public branch that has not been updated since August 2024. It leaks when compiled with Clang and `-Os -flto` or `-Oz -flto`, because its constant-time selection (`cmov`) lacks the value barrier that the current `main` branch has.

The current `main` branch, mlkem-native, PQClean and OpenSSL are **not affected** in any configuration we tested. We are in the process of notifying the pq-crystals maintainers. We did not build a key-recovery attack.

---

## Audited code

| Implementation | Repository | Version | Notes |
|---|---|---|---|
| pq-crystals reference | `pq-crystals/kyber` (`ref/`) | `main` `3edd5af`; `standard` `d5b791c` | Controls: `b628ba7` (vulnerable to CVE-2024-37880) and `9b8d306` (fix) |
| mlkem-native | `pq-code-package/mlkem-native` | v2.0.0 (`d1b2fe78`) | Portable C backend, assembly value barrier |
| PQClean | `PQClean/PQClean` | `0586a824` | `clean` implementation; repository archived |
| OpenSSL | `openssl/openssl` | 3.5.9 (`45e844fa`) | Only `crypto/ml_kem/ml_kem.c` is recompiled per configuration |

## Compilers and flags

- **Clang:** 15.0.7, 16.0.6, 17.0.6, 18.1.3, 19.1.1, 20.1.2 (Ubuntu 24.04) and 21.1.8, 22.1.8 (apt.llvm.org).
- **GCC:** 11.5.0, 12.4.0, 13.3.0, 14.2.0 (Ubuntu 24.04).
- **Standard flag set:** `-O0`, `-O1`, `-O2`, `-O3`, `-Os`, `-O2` without vectorization.
- **Extended flag set:** `-O1/-O2/-O3/-Os/-Oz` with `-flto`, `-O2/-Os` with `-march=native`, and `-Oz`.
- **Parameter sets:** ML-KEM-512, 768 and 1024. **Architecture:** x86-64.

---

## Repository layout

```
harness.c, harness_v2.c       Valgrind harnesses for pq-crystals (v1: 1 key; v2: 10 keys)
harness_mlkem_native.c        Valgrind harness for mlkem-native
harness_pqclean.c             Valgrind harness for PQClean
harness_openssl.c             Valgrind harness for OpenSSL (internal ossl_ml_kem_* API)
matriz.sh                     Compiler x flag matrix for pq-crystals
matriz_mn.sh                  Matrix for mlkem-native   (modes: CANARIO, ABLACION, BARRIER=volatile)
matriz_pqc.sh                 Matrix for PQClean        (modes: CANARIO, ABLACION)
matriz_ossl.sh                Matrix for OpenSSL        (modes: CANARIO, ABLACION)
dudect_frommsg.c              dudect test for poly_frommsg (CVE-2024-37880)
dudect_decaps*.c              dudect tests for decapsulation (pq-crystals, PQClean, OpenSSL)
resultados.csv                One row per analyzed configuration
logs/                         Valgrind reports, dudect logs, CPU conditions of the timing machine
```

The audited libraries are **not** stored in this repository; clone them at the commits listed above.

### `resultados.csv` columns

`fecha, libreria, commit, rol, operacion, kyber_k, compilador, version_compilador, flags, harness, iteraciones, decaps_ok, decaps_total, reportes_valgrind, ubicaciones_fuga, detalle_ubicaciones, notas`

`rol` is one of `auditoria` (audit), `control_positivo`, `control_negativo` or `ablacion_sin_barrier` (barrier removed). `ubicaciones_fuga` counts distinct source locations with a leak; `detalle_ubicaciones` lists them.

---

## How to reproduce

### Requirements (Ubuntu 24.04)

```bash
sudo apt install -y build-essential git valgrind python3 perl \
    clang-15 clang-16 clang-17 clang-18 clang-19 clang-20 gcc-11 gcc-12 gcc-13 gcc-14
wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && sudo ./llvm.sh 21 && sudo ./llvm.sh 22
```

### Get the code

```bash
git clone https://github.com/BR2903/ct-audit.git && cd ct-audit
git clone https://github.com/pq-crystals/kyber.git
git clone https://github.com/pq-code-package/mlkem-native.git && (cd mlkem-native && git checkout v2.0.0)
git clone https://github.com/PQClean/PQClean.git && (cd PQClean && git checkout 0586a824)
git clone --depth 1 --branch openssl-3.5.9 https://github.com/openssl/openssl.git openssl-3.5.9
(cd openssl-3.5.9 && ./Configure linux-x86_64 no-shared no-tests no-docs no-apps -g && make -j"$(nproc)" build_libs)
```

### Run the matrices

```bash
CC_ALL="clang-15 clang-16 clang-17 clang-18 clang-19 clang-20 clang-21 clang-22 gcc-11 gcc-12 gcc-13 gcc-14"
EXT="-O1 -flto;-O2 -flto;-O3 -flto;-Os -flto;-Oz -flto;-O2 -march=native;-Os -march=native;-Oz"

# Audit (standard flag set, then extended flag set)
./matriz.sh      auditoria main          "2 3 4"        "$CC_ALL"
FLAGS="$EXT" ./matriz.sh auditoria main  "2 3 4"        "$CC_ALL"
./matriz_mn.sh   auditoria v2.0.0        "512 768 1024" "$CC_ALL"
./matriz_pqc.sh  auditoria 0586a824      "512 768 1024" "$CC_ALL"
./matriz_ossl.sh auditoria openssl-3.5.9 "512 768 1024" "$CC_ALL"

# Positive controls
./matriz.sh control_positivo b628ba7 "2" "$CC_ALL"                                   # CVE-2024-37880
CANARIO=1 ./matriz_mn.sh control_positivo v2.0.0 "512 768 1024" "clang-18 gcc-14"    # injected branch

# Ablations (value barriers removed in temporary copies; sources are never modified)
ABLACION=1 FLAGS="-Os -flto;-Oz -flto" ./matriz_pqc.sh ablacion_sin_barrier 0586a824 "512 768 1024" "$CC_ALL"
ABLACION=1 ./matriz_ossl.sh ablacion_sin_barrier openssl-3.5.9 "512 768 1024" "$CC_ALL"
```

Each configuration takes about 2–3 seconds. Results are appended to `resultados.csv`.

> When running Valgrind inside Docker, lower the file-descriptor limit first: `ulimit -n 1024`.

### Timing measurements (dudect)

dudect tests must run on bare metal (not in a virtual machine). We disabled frequency boost, set the `performance` governor and pinned the process to one core:

```bash
echo 0 | sudo tee /sys/devices/system/cpu/cpufreq/boost
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
timeout 600 taskset -c 2 stdbuf -oL ./dudect_binary > logs/result.txt
```

The decapsulation tests compare valid ciphertexts with ciphertexts that have one bit flipped, which differ only in the implicit-rejection bit. With link-time optimization, always verify with `objdump` that the measured binary contains the expected instruction pattern, since the surrounding program changes the generated code.

---

## Limitations

- Valgrind finds leaks but cannot prove their absence: it only observes the executed paths (10 key pairs per binary).
- Variable-time instructions (as in KyberSlash) are not analyzed.
- Only ML-KEM decapsulation, on x86-64, with Clang and GCC.
- Timing results come from a single microarchitecture (AMD Zen 3+).
- We show measurable timing differences, not key-recovery attacks.
- For OpenSSL, only `ml_kem.c` varies with the compiler; the rest of `libcrypto` is built once with GCC.

## References

- M. Schneider *et al.*, "Breaking Bad: How compilers break constant-time implementations," ASIA CCS 2025. arXiv:2410.13489.
- A. Purnal, "clangover," 2024. https://github.com/antoonpurnal/clangover (CVE-2024-37880).
- D. J. Bernstein *et al.*, "KyberSlash," IACR TCHES 2025(2).
- A. Langley, "Checking that functions are constant time with Valgrind" (ctgrind), 2010.
- O. Reparaz, J. Balasch, I. Verbauwhede, "Dude, is my code constant time?" DATE 2017.
- NIST, FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard, 2024.
