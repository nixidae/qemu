/*
 * Apple VM hypercall services (SMCCC over HVC #0).
 *
 * The vmapple kernel never writes a pointer-authentication key register.
 * Firmware (AVPBooter, LLB, iBoot) programs the architected APIA/APIB/APDA/
 * APDB/APGA keys once on the boot CPU, the kernel enables them through
 * SCTLR_EL1, and everything else about PAC goes to the hypervisor as an
 * "Apple CPU service" call (xnu osfmk/arm64/hv_hvc.h):
 *
 *   0xc1000000  VMAPPLE_PAC_SET_INITIAL_STATE   each core's start path,
 *                                               before SCTLR enables PAC
 *   0xc1000001  VMAPPLE_PAC_GET_DEFAULT_KEYS    x2/x3 = default ROP/JOP pids
 *   0xc1000002  VMAPPLE_PAC_SET_A_KEYS
 *   0xc1000003  VMAPPLE_PAC_SET_B_KEYS
 *   0xc1000004  VMAPPLE_PAC_SET_EL0_DIVERSIFIER
 *   0xc1000005  VMAPPLE_PAC_SET_EL0_DIVERSIFIER_AT_EL1
 *   0xc1000006  VMAPPLE_PAC_SET_G_KEY
 *   0xc10000f0  VMAPPLE_PAC_NOP
 *
 * This implements that contract with architected PAC only, which is what a
 * generic arm64 host (KVM, Hyper-V) can offer:
 *
 * - SET_INITIAL_STATE on the boot CPU records the keys firmware left there;
 *   on any other core it installs them. A core started by PSCI CPU_ON comes
 *   out of reset with zero keys, and this is where Apple's hypervisor gives
 *   it the machine's.
 * - Every per-process key and diversifier request succeeds and changes
 *   nothing, so the kernel and every process share one key set. Signing
 *   stays self-consistent; only cross-process PAC isolation is given up.
 *
 * Every call returns 0: xnu 26 spins on `cbnz x0, .` after most of them.
 * GET_DEFAULT_KEYS hands out one random, non-zero ROP/JOP pid pair per boot;
 * with zero pids launchd dies with SIGBUS right after dyld starts ("initproc
 * failed to start -- exit reason namespace 2 subcode 0xa").
 *
 * Copyright (c) 2026 Youssef Elliethy (yaelliethy)
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/core/boards.h"
#include "hw/core/cpu.h"
#include "system/memory.h"
#include "system/hvf.h"
#include "system/kvm.h"
#include "system/tcg.h"
#include "qemu/timer.h"
#include "qemu/error-report.h"
#include "qemu/guest-random.h"
#include "qemu/units.h"
#include "hw/vmapple/hvc.h"
#include "target/arm/cpu.h"
#include "target/arm/kvm_arm.h"
#include "target/arm/smccc.h"

/* SMCCC fast calls, SMC64 convention, owner 1 (CPU service). */
#define VMAPPLE_CPU_SERVICE_BASE        0xc1000000u
#define VMAPPLE_CPU_SERVICE_COUNT       0x10000u

#define VMAPPLE_PAC_SET_INITIAL_STATE   0x00
#define VMAPPLE_PAC_GET_DEFAULT_KEYS    0x01

static struct {
    bool valid;
    ARMPACKey apia, apib, apda, apdb, apga;
} boot_keys;

static uint64_t default_pids[2];

static void keys_save(CPUARMState *env)
{
    boot_keys.apia = env->keys.apia;
    boot_keys.apib = env->keys.apib;
    boot_keys.apda = env->keys.apda;
    boot_keys.apdb = env->keys.apdb;
    boot_keys.apga = env->keys.apga;
    boot_keys.valid = true;
}

static void keys_install(CPUARMState *env)
{
    env->keys.apia = boot_keys.apia;
    env->keys.apib = boot_keys.apib;
    env->keys.apda = boot_keys.apda;
    env->keys.apdb = boot_keys.apdb;
    env->keys.apga = boot_keys.apga;
}

/*
 * Apple firmware assumes a 24 MHz system counter. The device tree iBoot hands
 * the kernel carries /cpus/<cpu>/timebase-frequency = 24000000, and xnu's
 * pe_identify_machine() takes the kernel's timebase from that property (or a
 * built-in 24 MHz) -- it never reads CNTFRQ_EL0. Under KVM or WHPX the guest
 * reads the host's real counter, which the hypervisor cannot rescale, so on a
 * host whose counter is not 24 MHz every guest time conversion is off by the
 * ratio.
 *
 * The boot CPU's SET_INITIAL_STATE comes from start.s with the MMU still off,
 * before arm_init() -> PE_init_platform() -> pe_identify_machine() reads the
 * device tree and rtclock_early_init() builds the clock from it. Correcting
 * the property here, in the copy iBoot already verified and loaded, gives the
 * kernel the real rate from its first tick.
 *
 * ADT property record: char name[32]; uint32_t length (bit 31 is a flag);
 * value[length]. Only a record with that exact name, length 8 and the value
 * 24000000 is rewritten.
 */
#define APPLE_TIMEBASE_HZ       24000000ULL
#define ADT_NAME_LEN            32
#define DT_SCAN_BYTES           (2 * GiB)

/* The rate of the counter the guest reads. */
static uint64_t guest_counter_hz(ARMCPU *cpu)
{
#ifdef __aarch64__
    /*
     * Under a hardware accelerator the guest reads the host's counter.
     * WHPX copies CNTFRQ_EL0 into gt_cntfrq_hz at vCPU creation; KVM does
     * not, so ask the host directly (Linux and Windows allow EL0 reads).
     */
    if (!tcg_enabled()) {
        uint64_t hz;

        asm volatile("mrs %0, cntfrq_el0" : "=r"(hz));
        return hz;
    }
#endif
    return cpu->gt_cntfrq_hz;
}

/* @rec starts with the property name; true if it held 24 MHz and now @hz. */
static bool patch_timebase_record(uint8_t *rec, uint64_t hz)
{
    uint32_t len;
    uint64_t val;

    memcpy(&len, rec + ADT_NAME_LEN, sizeof(len));
    memcpy(&val, rec + ADT_NAME_LEN + 4, sizeof(val));
    if ((le32_to_cpu(len) & 0x7fffffff) != 8 ||
        le64_to_cpu(val) != APPLE_TIMEBASE_HZ) {
        return false;
    }
    val = cpu_to_le64(hz);
    memcpy(rec + ADT_NAME_LEN + 4, &val, sizeof(val));
    return true;
}

static void fix_dt_timebase(ARMCPU *cpu)
{
    static const char name[ADT_NAME_LEN] = "timebase-frequency";
    uint64_t hz = guest_counter_hz(cpu);
    MemoryRegion *ram = current_machine->ram;
    uint8_t *base = memory_region_get_ram_ptr(ram);
    uint8_t *end = base + MIN(memory_region_size(ram), DT_SCAN_BYTES) -
                   (ADT_NAME_LEN + 4 + 8);
    uint8_t *rec;
    int patched = 0;

    if (hz == APPLE_TIMEBASE_HZ) {
        return;
    }
    for (rec = memmem(base, end - base, name, sizeof(name)); rec;
         rec = memmem(rec + 1, end - rec - 1, name, sizeof(name))) {
        patched += patch_timebase_record(rec, hz);
    }
    warn_report("vmapple: counter runs at %" PRIu64 " Hz; rewrote %d device "
                "tree timebase-frequency record(s) from 24 MHz", hz, patched);
}

#define INSN_HVC0           0xd4000002u
#define INSN_HVC1           0xd4000022u

/*
 * HVF's host kernel answers `hvc #0` with an Apple CPU service ID
 * (0xc1......) itself and never exits; `hvc #1` exits, and QEMU treats
 * every HVC immediate alike. The boot CPU's SET_INITIAL_STATE comes before
 * most of the kernel has run, so every call site is rewritten here once.
 */
static void patch_apple_hvc_sites(void)
{
    MemoryRegion *ram = current_machine->ram;
    uint32_t *words = memory_region_get_ram_ptr(ram);
    size_t n = MIN(memory_region_size(ram), DT_SCAN_BYTES) / 4;
    size_t i;
    int total = 0, patched = 0;

    for (i = 1; i + 1 < n; i++) {
        if (le32_to_cpu(words[i]) != INSN_HVC0) {
            continue;
        }
        total++;
        /* Callers also load x0 elsewhere and call shared wrappers. */
        bool patch = true;
        if (getenv("VMAPPLE_HVC_DUMP") && i >= 6) {
            info_report("hvc-site pa=0x%" PRIx64 " %s %08x %08x %08x %08x "
                        "%08x %08x [%08x] %08x %08x",
                        (uint64_t)0x70000000 + i * 4,
                        patch ? "patch" : "skip ",
                        le32_to_cpu(words[i - 6]), le32_to_cpu(words[i - 5]),
                        le32_to_cpu(words[i - 4]), le32_to_cpu(words[i - 3]),
                        le32_to_cpu(words[i - 2]), le32_to_cpu(words[i - 1]),
                        le32_to_cpu(words[i]), le32_to_cpu(words[i + 1]),
                        le32_to_cpu(words[i + 2]));
        }
        if (patch) {
            words[i] = cpu_to_le32(INSN_HVC1);
            patched++;
        }
    }
    warn_report("vmapple: rewrote %d of %d `hvc #0` words to `hvc #1`",
                patched, total);
}

static void set_initial_state(ARMCPU *cpu)
{
    if (CPU(cpu) == first_cpu) {
        fix_dt_timebase(cpu);
        if (hvf_enabled()) {
            patch_apple_hvc_sites();
        }
        keys_save(&cpu->env);
    } else if (boot_keys.valid) {
        keys_install(&cpu->env);
    }
}

static bool vmapple_hvc(ARMCPU *cpu, uint64_t x[8])
{
    uint32_t fid = x[0];

    if (fid - VMAPPLE_CPU_SERVICE_BASE >= VMAPPLE_CPU_SERVICE_COUNT) {
        return false;
    }
    switch (fid & 0xffff) {
    case VMAPPLE_PAC_SET_INITIAL_STATE:
        set_initial_state(cpu);
        break;
    case VMAPPLE_PAC_GET_DEFAULT_KEYS:
        x[2] = default_pids[0];
        x[3] = default_pids[1];
        break;
    }
    x[0] = 0;
    return true;
}

void vmapple_hvc_reset(void)
{
    boot_keys.valid = false;
    do {
        qemu_guest_getrandom_nofail(default_pids, sizeof(default_pids));
    } while (!default_pids[0] || !default_pids[1]);
}

/*
 * Under HVF a vCPU stuck after a swallowed Apple hypercall spins with
 * interrupts masked and never exits; target/arm/hvf/hvf.c serves the call
 * on a kick, and this timer provides the kicks.
 */
#define HVF_KICK_MS 10

static QEMUTimer *hvf_kick_timer;

static void hvf_kick_all(void *opaque)
{
    CPUState *cs;

    CPU_FOREACH(cs) {
        qemu_cpu_kick(cs);
    }
    timer_mod(hvf_kick_timer,
              qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + HVF_KICK_MS);
}

void vmapple_hvc_init(void)
{
    arm_smccc_set_handler(vmapple_hvc);
    if (kvm_enabled()) {
        kvm_arm_smccc_forward(VMAPPLE_CPU_SERVICE_BASE,
                              VMAPPLE_CPU_SERVICE_COUNT);
    }
    if (hvf_enabled()) {
        hvf_kick_timer = timer_new_ms(QEMU_CLOCK_REALTIME, hvf_kick_all, NULL);
        timer_mod(hvf_kick_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + HVF_KICK_MS);
    }
}
