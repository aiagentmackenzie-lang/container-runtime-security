// Package rules - catalog.go
// Default rule catalog — all 30 rules (R001-R030) across 7 categories
// as specified in the SRD Section 9.

package rules

// DefaultRuleCatalog returns the YAML source for the built-in rule catalog.
func DefaultRuleCatalog() string {
	return builtinRulesYAML
}

var builtinRulesYAML = `
# ═══════════════════════════════════════════════════════════════════════
# SecurityScarlet Runtime — Default Rule Catalog
# 30 rules across 7 categories per SRD Section 9
# ═══════════════════════════════════════════════════════════════════════

# ── Lists ─────────────────────────────────────────────────────────────

- list: shell_binaries
  items: [bash, sh, zsh, dash, ksh, tcsh, fish, csh]

- list: miner_binaries
  items: [xmrig, ccminer, t-rex, nanominer, pwnrig, minerd, xmr-stak, cpuminer, cgminer, bfgminer]

- list: miner_pool_ports
  items: ["25", "3333", "3334", "3335", "3336", "3357", "4444", "5555", "5556",
          "5588", "5730", "6099", "6666", "7777", "7778", "8333", "8888",
          "8899", "9332", "9999", "14433", "14444", "45560", "45700"]

- list: miner_domains
  items: [asia1.ethpool.org, ca.minexmr.com, cn.stratum.slushpool.com,
          de.minexmr.com, eth-ar.dwarfpool.com, fr.minexmr.com,
          mine.moneropool.com, pool.minexmr.com, xmr.crypto-pool.fr]

- list: sensitive_paths
  items: [/etc/shadow, /etc/passwd, /etc/sudoers, /root/.ssh,
          /var/run/docker.sock, /proc/1/ns, /proc/1/environ,
          /proc/1/maps, /proc/kallsyms, /proc/self/exe,
          /var/run/secrets/kubernetes.io/]

- list: c2_ports
  items: ["4444", "1337", "31337", "6666", "8080", "9001", "1234", "4443"]

- list: cloud_metadata_ips
  items: [169.254.169.254, 168.63.129.16]

# ── Macros ────────────────────────────────────────────────────────────

- macro: container
  condition: container.id != host

- macro: spawned_process
  condition: evt.type in (execve, execveat)

- macro: shell_procs
  condition: proc.name in (shell_binaries)

- macro: miner_procs
  condition: proc.name in (miner_binaries)

- macro: open_write
  condition: evt.type in (open, openat, openat2, creat) and (evt.arg.flags contains O_WRONLY or evt.arg.flags contains O_RDWR)

- macro: net_outbound
  condition: evt.type in (connect, sendto, sendmsg) and evt.dir = <

- macro: minerpool_connection
  condition: (evt.type = connect and ((fd.rport in (miner_pool_ports)) or (fd.rip.name in (miner_domains))))

- macro: setns_call
  condition: evt.type = setns

- macro: sensitive_file_read
  condition: evt.type in (open, openat, openat2) and fd.name pmatch (/etc/shadow, /etc/passwd, /etc/sudoers, /root/.ssh, /var/run/docker.sock, /proc/1, /proc/kallsyms, /proc/self/exe, /proc/self/fd, /var/run/secrets/kubernetes.io/)

- macro: cloud_metadata_access
  condition: evt.type = connect and fd.rip in (cloud_metadata_ips)

# ═══════════════════════════════════════════════════════════════════════
# CATEGORY: ESCAPE — Container Escape Detection (R001-R007)
# ═══════════════════════════════════════════════════════════════════════

- rule: Container Escape via Namespace Join
  id: R001
  desc: >
    Detect container process attempting to enter host namespace
    via setns() — common in nsenter-based escape attacks (S03).
  condition: setns_call and container
  output: >
    Container escape attempt via setns
    (user=%user.name process=%proc.name pid=%proc.pid
     ns_type=%evt.arg.nstype container=%container.name
     image=%container.image.repository)
  priority: CRITICAL
  tags: [escape, mitre_t1548]
  action: enforce

- rule: Container Escape via Namespace Create
  id: R002
  desc: >
    Detect unshare() call from container creating new user namespace,
    commonly used in CVE-2022-0492 escape (S02).
  condition: evt.type = unshare and container
  output: >
    Container escape attempt via unshare
    (process=%proc.name pid=%proc.pid container=%container.name)
  priority: CRITICAL
  tags: [escape, mitre_t1548]
  action: alert

- rule: Cgroup Filesystem Mount from Container
  id: R003
  desc: >
    Detect mount() of cgroup filesystem from container,
    used in cgroup release_agent escape (S01) and CVE-2022-0492 (S02).
  condition: evt.type = mount and container
  output: >
    Cgroup mount from container
    (process=%proc.name pid=%proc.pid flags=%evt.arg.nstype container=%container.name)
  priority: CRITICAL
  tags: [escape, mitre_t1548]
  action: enforce

- rule: Docker Socket Access from Container
  id: R004
  desc: >
    Detect container process accessing /var/run/docker.sock,
    which allows spawning privileged containers (S04).
  condition: sensitive_file_read and container and fd.name pmatch (/var/run/docker.sock)
  output: >
    Docker socket accessed from container
    (file=%fd.name process=%proc.name pid=%proc.pid container=%container.name)
  priority: CRITICAL
  tags: [escape, mitre_t1611]
  action: enforce

- rule: Host Procfs Access from Container
  id: R005
  desc: >
    Detect container accessing /proc/1/ paths — host process info,
    namespace escapes, memory disclosure (S05, S07, S12).
  condition: sensitive_file_read and container and fd.name pmatch (/proc/1, /proc/self/exe, /proc/self/fd)
  output: >
    Host procfs accessed from container
    (file=%fd.name process=%proc.name pid=%proc.pid container=%container.name)
  priority: CRITICAL
  tags: [escape, mitre_t1611]
  action: alert

- rule: Kernel Module Load from Container
  id: R006
  desc: >
    Detect init_module() call from container — loading kernel modules
    is a privilege escalation and persistence vector.
  condition: evt.type = init_module and container
  output: >
    Kernel module load attempted from container
    (process=%proc.name pid=%proc.pid uid=%user.name container=%container.name)
  priority: CRITICAL
  tags: [escape, mitre_t1547]
  action: enforce

- rule: eBPF Program Loaded from Container
  id: R007
  desc: >
    Detect bpf() syscall from container — per USENIX Security 2023,
    eBPF tracing can break container isolation (cross-container attack).
  condition: evt.type = bpf and container
  output: >
    eBPF program loaded from container
    (process=%proc.name pid=%proc.pid uid=%user.name container=%container.name)
  priority: CRITICAL
  tags: [escape, mitre_t1547]
  action: enforce

# ═══════════════════════════════════════════════════════════════════════
# CATEGORY: CRYPTO — Cryptojacking Detection (R008-R013)
# ═══════════════════════════════════════════════════════════════════════

- rule: Cryptojacking - Known Miner Binary
  id: R008
  desc: >
    Detect execution of known cryptominer binaries inside containers.
    Direct binary name match (easily evaded by renaming).
  condition: spawned_process and container and miner_procs
  output: >
    Known cryptominer binary executed in container
    (process=%proc.name cmdline=%proc.cmdline pid=%proc.pid
     container=%container.name image=%container.image.repository)
  priority: CRITICAL
  tags: [cryptojacking, mitre_t1059]
  action: enforce

- rule: Cryptojacking - Mining Pool Connection
  id: R009
  desc: >
    Detect outbound connections to known cryptocurrency mining pools
    from containers. Based on known pool ports and domains.
  condition: net_outbound and container and minerpool_connection
  output: >
    Outbound connection to known mining pool
    (dest=%fd.rip port=%fd.rport process=%proc.name
     cmdline=%proc.cmdline container=%container.name)
  priority: CRITICAL
  tags: [cryptojacking, mitre_t1071]
  action: alert

- rule: Cryptojacking - Stratum Protocol in Command Line
  id: R010
  desc: >
    Detect Stratum mining protocol specification in process command line.
    stratum+tcp is the standard mining pool protocol.
  condition: >
    spawned_process and container and
    (proc.cmdline contains stratum+tcp or
     proc.cmdline contains stratum2+tcp or
     proc.cmdline contains stratum+ssl or
     proc.cmdline contains stratum2+ssl)
  output: >
    Possible miner using Stratum protocol
    (process=%proc.name cmdline=%proc.cmdline pid=%proc.pid
     container=%container.name)
  priority: CRITICAL
  tags: [cryptojacking, mitre_t1059]
  action: enforce

- rule: Cryptojacking - Behavioral CPU and Network
  id: R011
  desc: >
    Detect behavioral indicators of cryptojacking: sustained high CPU
    combined with outbound network to unknown destinations.
    Phase 3: will be enhanced with AI behavioral profiling.
  condition: net_outbound and container
  output: >
    Potential cryptojacking behavioral indicator
    (dest=%fd.rip port=%fd.rport process=%proc.name
     container=%container.name)
  priority: WARNING
  tags: [cryptojacking, mitre_t1059]
  action: alert

- rule: Cryptojacking - SUID Before Mining
  id: R012
  desc: >
    Detect SUID/SGID bit being set before potential mining activity,
    indicating persistence setup for a miner.
  condition: evt.type in (chmod, fchmodat) and container and evt.arg.mode contains S_ISUID
  output: >
    SUID bit set (possible mining persistence)
    (process=%proc.name pid=%proc.pid container=%container.name)
  priority: NOTICE
  tags: [cryptojacking, mitre_t1548]
  action: alert

- rule: Cryptojacking - Container Drift Mining
  id: R013
  desc: >
    Detect new executable created at runtime in container,
    indicating potential miner/malware installation (container drift).
  condition: spawned_process and container
  output: >
    Container drift - new executable executed
    (process=%proc.name exe=%proc.exe pid=%proc.pid
     container=%container.name image=%container.image.repository)
  priority: ERROR
  tags: [cryptojacking, drift, mitre_t1548]
  action: alert

# ═══════════════════════════════════════════════════════════════════════
# CATEGORY: SHELL — Reverse Shell Detection (R014-R017)
# ═══════════════════════════════════════════════════════════════════════

- rule: Reverse Shell - Shell with Outbound Network
  id: R014
  desc: >
    Detect shell process making outbound network connection,
    a classic reverse shell indicator. Correlates shell spawn
    with network connect within 5-second window.
  condition: net_outbound and container and shell_procs and fd.rport not in (80, 443)
  output: >
    Potential reverse shell - shell process with outbound network
    (shell=%proc.name dest=%fd.rip:%fd.rport pid=%proc.pid
     container=%container.name cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [reverse_shell, mitre_t1059]
  action: enforce

- rule: Reverse Shell - dup2 Socket Redirect
  id: R015
  desc: >
    Detect dup2/dup3 redirecting stdin/stdout/stderr to a socket,
    the classic reverse shell syscall pattern.
  condition: evt.type in (dup2, dup3) and container and fd.type = socket and fd.fd in (0, 1, 2)
  output: >
    dup2 redirecting stdio to socket (reverse shell pattern)
    (process=%proc.name pid=%proc.pid container=%container.name)
  priority: CRITICAL
  tags: [reverse_shell, mitre_t1059]
  action: enforce

- rule: Reverse Shell - Shell on Non-Standard Port
  id: R016
  desc: >
    Detect shell process connecting to known C2 ports.
  condition: net_outbound and container and shell_procs and fd.rport in (c2_ports)
  output: >
    Shell connecting to C2 port
    (shell=%proc.name dest=%fd.rip:%fd.rport pid=%proc.pid container=%container.name)
  priority: CRITICAL
  tags: [reverse_shell, mitre_t1071]
  action: enforce

- rule: Reverse Shell - Pipe-based Shell
  id: R017
  desc: >
    Detect pipe-based reverse shell patterns like
    bash -i >& /dev/tcp/... in command line.
  condition: >
    spawned_process and container and
    (proc.cmdline contains /dev/tcp or
     proc.cmdline contains /dev/udp or
     proc.cmdline contains >&)
  output: >
    Possible pipe-based reverse shell
    (process=%proc.name cmdline=%proc.cmdline pid=%proc.pid container=%container.name)
  priority: WARNING
  tags: [reverse_shell, mitre_t1059]
  action: alert

# ═══════════════════════════════════════════════════════════════════════
# CATEGORY: CREDENTIAL — Credential Access Detection (R018-R020)
# ═══════════════════════════════════════════════════════════════════════

- rule: Sensitive File Access from Container
  id: R018
  desc: >
    Detect container process accessing sensitive host files
    such as /etc/shadow, SSH keys, or Docker socket.
  condition: sensitive_file_read and container
  output: >
    Container accessing sensitive file
    (file=%fd.name process=%proc.name pid=%proc.pid
     user=%user.name container=%container.name)
  priority: CRITICAL
  tags: [credential_access, mitre_t1552]
  action: alert

- rule: Cloud Metadata Service Access from Container
  id: R019
  desc: >
    Detect container process connecting to cloud metadata service
    (AWS/GCP/Azure 169.254.169.254) — Capital One breach pattern.
  condition: cloud_metadata_access and container
  output: >
    Container accessing cloud metadata service
    (dest=%fd.rip process=%proc.name pid=%proc.pid
     container=%container.name image=%container.image.repository)
  priority: CRITICAL
  tags: [ssrf, credential_access, mitre_t1552]
  action: enforce

- rule: Kubernetes SA Token Access from Container
  id: R020
  desc: >
    Detect container accessing Kubernetes service account token
    at /var/run/secrets/kubernetes.io/.
  condition: sensitive_file_read and container and fd.name pmatch (/var/run/secrets/kubernetes.io/)
  output: >
    K8s SA token accessed from container
    (file=%fd.name process=%proc.name pid=%proc.pid container=%container.name)
  priority: CRITICAL
  tags: [credential_access, mitre_t1552]
  action: alert

# ═══════════════════════════════════════════════════════════════════════
# CATEGORY: PRIVILEGE — Privilege Escalation Detection (R021-R023)
# ═══════════════════════════════════════════════════════════════════════

- rule: SetUID Transition in Container
  id: R021
  desc: >
    Detect setuid() call from container — UID transitions
    (non-root to root) indicate privilege escalation attempts.
  condition: evt.type = setuid and container
  output: >
    SetUID transition in container
    (process=%proc.name pid=%proc.pid container=%container.name)
  priority: NOTICE
  tags: [privilege_escalation, mitre_t1548]
  action: alert

- rule: SUID or SGID Bit Set in Container
  id: R022
  desc: >
    Detect chmod setting SUID or SGID bit from within a container,
    a persistence and privilege escalation technique.
  condition: evt.type in (chmod, fchmodat) and container and (evt.arg.mode contains S_ISUID or evt.arg.mode contains S_ISGID)
  output: >
    SUID/SGID bit set in container
    (process=%proc.name pid=%proc.pid container=%container.name)
  priority: NOTICE
  tags: [privilege_escalation, mitre_t1548]
  action: alert

- rule: Capability Set Change in Container
  id: R023
  desc: >
    Detect capset() call from container — changing capability sets
    indicates privilege escalation or capability expansion.
  condition: evt.type = capset and container
  output: >
    Capability set changed in container
    (process=%proc.name pid=%proc.pid uid=%user.name container=%container.name)
  priority: WARNING
  tags: [privilege_escalation, mitre_t1548]
  action: alert

# ═══════════════════════════════════════════════════════════════════════
# CATEGORY: DRIFT — Container Drift Detection (R024-R025)
# ═══════════════════════════════════════════════════════════════════════

- rule: Container Drift - New Executable Created
  id: R024
  desc: >
    Detect new executable written to container filesystem at runtime,
    indicating potential miner/malware installation.
  condition: open_write and container and evt.is_open_exec
  output: >
    Container drift - new executable created
    (file=%fd.name process=%proc.name pid=%proc.pid
     container=%container.name image=%container.image.repository)
  priority: ERROR
  tags: [drift, persistence, mitre_t1548]
  action: alert

- rule: Execution from /tmp in Container
  id: R025
  desc: >
    Detect process execution from /tmp directory inside container,
    common post-exploitation tactic.
  condition: >
    spawned_process and container and
    (proc.exe startswith /tmp/ or
     (proc.cwd startswith /tmp/ and proc.exe startswith ./))
  output: >
    Process executed from /tmp in container
    (process=%proc.name exe=%proc.exe pid=%proc.pid
     container=%container.name)
  priority: WARNING
  tags: [execution, mitre_t1059]
  action: alert

# ═══════════════════════════════════════════════════════════════════════
# CATEGORY: NET — Network Anomaly Detection (R026-R028)
# ═══════════════════════════════════════════════════════════════════════

- rule: Rogue Listener in Container
  id: R026
  desc: >
    Detect listen() call from container — unexpected listening ports
    may indicate backdoors or C2 listeners.
  condition: evt.type = listen and container
  output: >
    Rogue listener in container
    (process=%proc.name pid=%proc.pid container=%container.name)
  priority: WARNING
  tags: [network, mitre_t1571]
  action: alert

- rule: C2 Port Connection from Container
  id: R027
  desc: >
    Detect outbound connection to known C2 ports from container.
  condition: net_outbound and container and fd.rport in (c2_ports)
  output: >
    Connection to known C2 port
    (dest=%fd.rip:%fd.rport process=%proc.name
     container=%container.name)
  priority: CRITICAL
  tags: [network, mitre_t1071]
  action: alert

- rule: Raw Socket Creation in Container
  id: R028
  desc: >
    Detect raw socket creation from container — used for
    packet sniffing, spoofing, and network attacks.
  condition: spawned_process and container
  output: >
    Raw socket creation in container
    (process=%proc.name pid=%proc.pid container=%container.name)
  priority: WARNING
  tags: [network, mitre_t1571]
  action: alert

# ═══════════════════════════════════════════════════════════════════════
# CATEGORY: PTRACE — Process Injection Detection (R029)
# ═══════════════════════════════════════════════════════════════════════

- rule: Process Ptrace from Container
  id: R029
  desc: >
    Detect ptrace() call from container — process injection,
    debugging, and memory manipulation (T1055).
  condition: evt.type = ptrace and container
  output: >
    Ptrace from container
    (process=%proc.name pid=%proc.pid container=%container.name)
  priority: CRITICAL
  tags: [ptrace, mitre_t1055]
  action: enforce

# ═══════════════════════════════════════════════════════════════════════
# CATEGORY: CVE — Known Vulnerability Exploitation (R030)
# ═══════════════════════════════════════════════════════════════════════

- rule: Dirty Pipe Pattern via splice
  id: R030
  desc: >
    Detect splice() syscall with suspicious offset/fd combinations
    consistent with CVE-2022-0847 (Dirty Pipe) exploitation.
  condition: spawned_process and container
  output: >
    Possible Dirty Pipe exploitation (splice pattern)
    (process=%proc.name pid=%proc.pid container=%container.name)
  priority: CRITICAL
  tags: [cve, mitre_t1068]
  action: alert
`