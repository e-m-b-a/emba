#!/bin/bash
#
# EMBA launcher wrapper
# Prompts for / accepts a firmware path plus common optional parameters,
# then invokes ./emba with the assembled arguments.
#
# Usage: ./run-emba.sh [-f firmware_path] [-l log_path] [-p profile] [-P max_mods] [-T max_mod_threads] [-u] [-C cpu_quota_pct] [-G reserved_cores] [-y] [-e "extra emba args"]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

usage() {
  cat <<EOF
Usage: $(basename "$0") -f <firmware_path> [options]

Required (will prompt interactively if omitted):
  -f <path>        Firmware file or directory to analyze

Options:
  -l <path>        Log output directory (default: ./logs/<firmware_name>_<timestamp>)
  -p <profile>     Scan profile name or path under ./scan-profiles (default: default-scan.emba)
  -P <num>         Max parallel modules (default: ceil(nproc/4), capped so nproc is not oversubscribed)
  -T <num>         Max threads per module (default: 4)
  -u               Unthrottled: let emba pick its own auto concurrency instead of the safe defaults above
                    (emba's auto mode can run MAX_MODS * MAX_MOD_THREADS far beyond nproc and has been
                    observed to push load average to 4x+ nproc, starving the desktop session)
  -C <pct|none>    Hard CPU quota (systemd cgroup CPUQuota) for the whole scan, in percent of one core
                    (default: (nproc-2)*100, i.e. leaves ~2 cores free for the desktop). This caps total
                    CPU time for the entire process tree, including tools like John the Ripper that spawn
                    their own internal threads and ignore -T. Pass "none" or 0 to disable this cap.
  -G <num|none>    Reserve this many CPU cores exclusively for the desktop/GPU, off-limits to the scan
                    (default: 4). Implemented via cgroup AllowedCPUs (cpuset), a hard kernel-enforced
                    placement restriction — unlike -C (a time-based quota), this guarantees a fixed set
                    of cores is never touched by scan threads, even in short bursts. This targets a crash
                    pattern where the GPU driver's own workqueue (drm_fb_helper_damage_work) shares a core
                    with a scan thread and stalls, even while total system load is well under the -C quota.
                    Pass "none" or 0 to disable.
  -y               Overwrite log directory automatically if not empty
  -e "<args>"      Extra raw arguments passed through to emba, quoted as one string
  -h               Show this help

Examples:
  $(basename "$0") -f ~/firmware/router.bin
  $(basename "$0") -f ~/firmware/router.bin -p quick-scan.emba -l ~/log/router
  $(basename "$0") -f ~/firmware/router.bin -P 8 -T 2
  $(basename "$0") -f ~/firmware/router.bin -u
  $(basename "$0") -f ~/firmware/router.bin -C 2000 -G 4
EOF
}

FW_PATH=""
LOG_PATH=""
PROFILE="default-scan.emba"
MAX_MODS=""
MAX_MOD_THREADS=""
UNTHROTTLED=0
CPU_QUOTA=""
GPU_RESERVE=""
OVERWRITE=0
EXTRA_ARGS=""

while getopts "f:l:p:P:T:uC:G:ye:h" OPT; do
  case "${OPT}" in
    f) FW_PATH="${OPTARG}" ;;
    l) LOG_PATH="${OPTARG}" ;;
    p) PROFILE="${OPTARG}" ;;
    P) MAX_MODS="${OPTARG}" ;;
    T) MAX_MOD_THREADS="${OPTARG}" ;;
    u) UNTHROTTLED=1 ;;
    C) CPU_QUOTA="${OPTARG}" ;;
    G) GPU_RESERVE="${OPTARG}" ;;
    y) OVERWRITE=1 ;;
    e) EXTRA_ARGS="${OPTARG}" ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

if [[ "${UNTHROTTLED}" -eq 1 && ( -n "${MAX_MODS}" || -n "${MAX_MOD_THREADS}" ) ]]; then
  echo "错误: -u 与 -P/-T 不能同时使用" >&2
  exit 1
fi

if [[ "${UNTHROTTLED}" -eq 0 ]]; then
  if [[ -z "${MAX_MODS}" ]]; then
    NPROC="$(nproc)"
    MAX_MODS=$(( (NPROC + 3) / 4 ))
    [[ "${MAX_MODS}" -lt 2 ]] && MAX_MODS=2
  fi
  [[ -z "${MAX_MOD_THREADS}" ]] && MAX_MOD_THREADS=4
fi

# Hard cgroup CPU quota for the whole scan (process tree). This is independent of -P/-T/-u:
# tools like John the Ripper auto-detect all CPU cores and spawn their own threads, which
# -T cannot bound since it only limits emba's own module scheduling.
CGROUP_ENABLED=0
if [[ "${CPU_QUOTA}" == "none" || "${CPU_QUOTA}" == "0" ]]; then
  CPU_QUOTA=""
elif [[ -z "${CPU_QUOTA}" ]]; then
  NPROC="$(nproc)"
  RESERVE_CORES=2
  [[ "${NPROC}" -le "${RESERVE_CORES}" ]] && RESERVE_CORES=1
  CPU_QUOTA=$(( (NPROC - RESERVE_CORES) * 100 ))
  [[ "${CPU_QUOTA}" -lt 100 ]] && CPU_QUOTA=100
  CGROUP_ENABLED=1
else
  CGROUP_ENABLED=1
fi

# Reserve a fixed set of cores the scan can never be scheduled on (cpuset, not just a time quota).
# This is a hard placement guarantee, unlike -C, and targets core-level contention with the GPU
# driver's own workqueues that a pure CPU-time quota does not prevent.
SCAN_CPU_RANGE=""
if [[ "${GPU_RESERVE}" == "none" || "${GPU_RESERVE}" == "0" ]]; then
  GPU_RESERVE=0
else
  [[ -z "${GPU_RESERVE}" ]] && GPU_RESERVE=4
  NPROC="$(nproc)"
  if [[ "${GPU_RESERVE}" -ge "${NPROC}" ]]; then
    echo "错误: -G 保留核心数 (${GPU_RESERVE}) 必须小于总核心数 (${NPROC})" >&2
    exit 1
  fi
  SCAN_CPU_MAX=$(( NPROC - GPU_RESERVE - 1 ))
  SCAN_CPU_RANGE="0-${SCAN_CPU_MAX}"
  CGROUP_ENABLED=1
fi

if [[ -z "${FW_PATH}" ]]; then
  read -rp "请输入固件路径 (firmware path): " FW_PATH
fi

# expand leading ~
FW_PATH="${FW_PATH/#\~/${HOME}}"

if [[ -z "${FW_PATH}" || ! -e "${FW_PATH}" ]]; then
  echo "错误: 固件路径不存在: ${FW_PATH}" >&2
  exit 1
fi
FW_PATH="$(cd "$(dirname "${FW_PATH}")" && pwd)/$(basename "${FW_PATH}")"

# resolve profile: accept bare name, relative or absolute path
if [[ -f "${PROFILE}" ]]; then
  : # already a valid path
elif [[ -f "${SCRIPT_DIR}/scan-profiles/${PROFILE}" ]]; then
  PROFILE="${SCRIPT_DIR}/scan-profiles/${PROFILE}"
else
  echo "错误: 扫描配置文件不存在: ${PROFILE}" >&2
  exit 1
fi

if [[ -z "${LOG_PATH}" ]]; then
  FW_NAME="$(basename "${FW_PATH}")"
  LOG_PATH="${SCRIPT_DIR}/logs/${FW_NAME}_$(date +%Y%m%d_%H%M%S)"
fi
LOG_PATH="${LOG_PATH/#\~/${HOME}}"
mkdir -p "${LOG_PATH}"

if [[ "${CGROUP_ENABLED}" -eq 1 ]]; then
  PROPS=(-p "CPUWeight=20")
  [[ -n "${CPU_QUOTA}" ]] && PROPS+=(-p "CPUQuota=${CPU_QUOTA}%")
  [[ -n "${SCAN_CPU_RANGE}" ]] && PROPS+=(-p "AllowedCPUs=${SCAN_CPU_RANGE}")
  CMD=(sudo systemd-run --scope --collect "--unit=emba-scan-$$" "${PROPS[@]}" -- ./emba -l "${LOG_PATH}" -f "${FW_PATH}" -p "${PROFILE}")
else
  CMD=(sudo ./emba -l "${LOG_PATH}" -f "${FW_PATH}" -p "${PROFILE}")
fi
[[ "${UNTHROTTLED}" -eq 0 ]] && CMD+=(-P "${MAX_MODS}" -T "${MAX_MOD_THREADS}")
[[ "${OVERWRITE}" -eq 1 ]] && CMD+=(-y)
if [[ -n "${EXTRA_ARGS}" ]]; then
  # shellcheck disable=SC2206
  EXTRA_ARR=(${EXTRA_ARGS})
  CMD+=("${EXTRA_ARR[@]}")
fi

echo "固件路径: ${FW_PATH}"
echo "日志路径: ${LOG_PATH}"
echo "扫描配置: ${PROFILE}"
if [[ "${UNTHROTTLED}" -eq 1 ]]; then
  echo "模块并发: 无 (emba 自动配置，可能导致负载远超 CPU 线程数)"
else
  echo "模块并发: 最多 ${MAX_MODS} 个模块并行，每个模块最多 ${MAX_MOD_THREADS} 线程"
fi
if [[ -n "${CPU_QUOTA}" ]]; then
  echo "CPU 时间配额: ${CPU_QUOTA}% (约 $(( CPU_QUOTA / 100 )) 核) — 覆盖整个扫描进程树，包括 john 等自行开多线程的工具"
else
  echo "CPU 时间配额: 无"
fi
if [[ -n "${SCAN_CPU_RANGE}" ]]; then
  echo "核心隔离: 扫描仅限使用核心 ${SCAN_CPU_RANGE}，为桌面/GPU 保留 ${GPU_RESERVE} 个核心 ($(( SCAN_CPU_MAX + 1 ))-$(( $(nproc) - 1 )))"
else
  echo "核心隔离: 无"
fi
echo "运行命令: ${CMD[*]}"
echo ""

exec "${CMD[@]}"
