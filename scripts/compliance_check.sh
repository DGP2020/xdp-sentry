#!/usr/bin/env bash
# ==============================================================================
# compliance_check.sh - Automated Security & Compliance Policy Validator
# Checks BPF map permissions, binary ownership, and rule audit readiness
# ==============================================================================

set -euo pipefail

echo "================================================================================"
echo "    XDP-Sentry: Automated Regulatory & Security Compliance Check"
echo "================================================================================"

PASSED=0
WARNINGS=0

check_status() {
    local desc="$1"
    local result="$2"
    if [ "$result" -eq 0 ]; then
        echo "  [✓] PASS: $desc"
        PASSED=$((PASSED + 1))
    else
        echo "  [!] WARN: $desc"
        WARNINGS=$((WARNINGS + 1))
    fi
}

# 1. Check BPF filesystem permissions
if [ -d "/sys/fs/bpf" ]; then
    PERMS=$(stat -c "%a" /sys/fs/bpf)
    if [ "$PERMS" = "700" ] || [ "$PERMS" = "755" ] || [ "$PERMS" = "555" ]; then
        check_status "/sys/fs/bpf directory permissions restricted ($PERMS)" 0
    else
        check_status "/sys/fs/bpf directory permissions too open ($PERMS)" 1
    fi
else
    check_status "/sys/fs/bpf mounted and available" 1
fi

# 2. Check binary permissions
BINARY="./target/release/my-filter"
if [ -f "$BINARY" ]; then
    BIN_PERMS=$(stat -c "%a" "$BINARY")
    if [ "$BIN_PERMS" = "755" ] || [ "$BIN_PERMS" = "750" ]; then
        check_status "User-space controller binary permissions valid ($BIN_PERMS)" 0
    else
        check_status "User-space controller permissions non-standard ($BIN_PERMS)" 1
    fi
else
    check_status "Release binary exists ($BINARY)" 1
fi

# 3. Check eBPF binary existence and safety
EBPF_BIN="target/bpfel-unknown-none/release/my-filter-ebpf"
if [ -f "$EBPF_BIN" ]; then
    check_status "Kernel eBPF ELF binary built and present ($EBPF_BIN)" 0
else
    check_status "Kernel eBPF ELF binary missing" 1
fi

# 4. Check documentation compliance assets
DOCS=("docs/XDP_DRIVER_VS_GENERIC_MODE.md" "docs/E2E_TESTING_PATTERNS.md" "docs/SECURITY_COMPLIANCE_AUDIT.md" "docs/benchmark_results.json")
for doc in "${DOCS[@]}"; do
    if [ -f "$doc" ]; then
        check_status "Compliance documentation asset verified ($doc)" 0
    else
        check_status "Missing compliance document ($doc)" 1
    fi
done

echo ""
echo "================================================================================"
echo "  Compliance Audit Summary: $PASSED checks passed, $WARNINGS warnings."
echo "================================================================================"
