# 🛡️ AISE - Advanced Infrastructure Secure Ecosystem - A Dual-Hardware Architecture to Protect Your AI Ecosystem (PoC)

![AISE Architecture Diagram](./AISE%20-%20Advanced%20Infrastructure%20Secure%20Ecosystem.png)

> 💡 **Project Status & Local Simulation Setup:**  
> This document defines a **Proof of Concept (PoC) architecture meant for single-PC simulation and step-by-step experimentation**. The dual-box ecosystem (Box A Linux + Box B OpenBSD) can be simulated locally on a single machine using hypervisors/VMs (QEMU/KVM, VirtualBox) and network namespaces.

---

## 🧠 The Problem
AI inference engines require complex frameworks running on Linux environments for hardware acceleration (GPUs). This attack surface exposes the ecosystem to severe application-level threats (prompt injection, data exfiltration, kernel exploits) and infrastructure-level risks (volumetric DDoS attacks) that saturate computing servers and disrupt AI services. 

This repository contains the formal architecture specification, security threat model, and network design for the AISE framework. Reference implementation scripts, eBPF drivers, and OpenBSD integration code will be released in upcoming commits during the development/refactoring phase.

---

## 🚀 The Proposed Architecture (The Global XDP Vision)
The entire ecosystem is structured so that network traffic passes through the **XDP (eXpress Data Path)** framework at the hardware/driver level. XDP manages network filtering, acting as an absolute low-level shield. System management, egress traffic, and repository updates are decoupled from the XDP fast-path and routed over a dedicated Optical Access Line (FTTx interface) directly through Box B. The external node (Box B running OpenBSD) is interconnected in such a way that it communicates with the network exclusively through this protective layer. The **eBPF CO-RE (Compile Once – Run Everywhere)** model allows the system to reuse the same compiled ELF object without requiring recompilation every time the Linux kernel is updated.

### 🔒 Advanced Security & L7 Egress Defense Model
The architecture employs an asymmetric defense mechanism—including how XDP validates L7 UDP teardown messages via exact socket-tuple match to prevent unauthorized client banning even if the Gateway is compromised.

---

### 🔒 Protocol Design: Why TCP Over UDP & QUIC?

While modern HTTP/3 and QUIC utilize UDP for low-latency transport, **AISE intentionally enforces TCP** across its control and proxy paths for deterministic state enforcement:

* **In-Kernel Sequence Validation (`seq_expected`):** TCP’s strict sequence numbering enables XDP to enforce RFC 793 in-window validation directly in BPF maps. This allows the fast-path to drop out-of-order, spoofed, or replayed packets before user-space processing.
* **Deterministic L4 State Machines:** TCP's strict state transitions (`SYN` -> `ESTABLISHED` -> `FIN`/`RST`) allow the Auth Verifier and XDP layer to maintain unambiguous flow states (`map_unauth` vs. `map_session`).
* **Zero-Alloc Silent Tarpitting:** Fast-path TCP teardowns (`SO_LINGER(0)`) permit Box A and Box B to drop connections instantly without transmitting `TCP RST` packets back to bad actors, trapping malicious scanners in socket timeouts without allocating kernel memory.

---

### 🎯 Scope & Ecosystem Focus

The primary objective of this Proof of Concept (PoC) is **Ecosystem & Network Security Architecture**—specifically, neutralizing L4/L7 volumetric, stateful, and protocol-level threats upstream of sensitive workloads. 

* **In-Scope:** Zero-trust packet filtering, eBPF/XDP driver execution, OpenBSD L7 process isolation (`pledge`/`unveil`), blind authentication state machines, and silent TCP tarpitting.
* **Out-of-Scope:** Proprietary LLM neural network design, custom GPU kernel development, or raw tensor sampling math. 

AISE treats downstream AI inference engines (such as vLLM, SGLang, or llama.cpp) as isolated compute backends, focusing entirely on making the surrounding infrastructure unassailable.

> 📝 **Detailed Specification Notice:**  
> The comprehensive technical specification for the L7 XDP/OpenBSD integration is maintained in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## 🚀 Key Architectural Innovations


* **Dual-Layer Asymmetric Shield (eBPF/XDP + OpenBSD):** Combines kernel-space line-rate packet filtering via Linux XDP with maximum L7 process isolation on OpenBSD (`pledge`/`unveil`). Malicious traffic is neutralized directly at the Network Interface Card (NIC) level before ever touching the operating system's TCP/IP stack.
* **Asymmetric AI Threat Isolation & Computational Offloading:** Ingress traffic undergoes high-isolation deterministic filtering on OpenBSD to absorb attack vectors that could compromise the OS. It is then forwarded to the Linux Gatekeeper for CPU-heavy tasks (e.g., token counting, entropy analysis) and dedicated inferer inspection, with full authority to apply direct blacklists via eBPF/XDP. Conversely, AI responses (*Egress*) bypass the Gatekeeper entirely to prevent supply-chain/egress compromise, relying solely on OpenBSD's deterministic isolation.
* **Blind Authentication & Synchronous 2-Way Control-Loop (`AUTH_CK` / `AUTH_UN` / `AUTH_OK`):** The user-space Auth Verifier remains completely "deaf" to incoming credentials until XDP confirms the L4 flow state via in-kernel `XDP_TX` probes. **Even cryptographically valid credentials are deterministically rejected** if submitted out-of-sequence, via unconfirmed sockets, or in violation of the single-attempt state machine. This fundamentally eliminates enumeration attacks, replay vectors, brute-force attempts, and internal database exposure to unvalidated sockets.
* **Zero-Trust Enforcement & Immediate Fraud Truncation:** The Auth Verifier enforces a strict *fail-closed* security policy. In the event of invalid credentials, malicious payloads, or fraud attempts:
  * **Zero State Allocation:** The Auth Verifier does not confirm authentication, preventing any entry write into the `map_session` eBPF map. The session is simply never created.
  * **Instant Truncation (`XDP_DROP`):** Without an active session registered in eBPF, XDP treats subsequent traffic as unauthorized and **drops it instantly at the network interface layer (L2/Driver)**. This prevents any further packet from consuming Kernel or OpenBSD memory/CPU resources.
* **Atomic Single Authentication Guarantee Per Session:** Enforces a deterministic state machine allowing strictly one active authentication attempt at a time per L4 session tuple (*One Auth at Once*). This mitigates race conditions, session overlapping, and state desynchronization during the verification process.
* **XDP-Driven Dynamic Anti-DDoS Policies:** Enables the control plane and analytics engine to dynamically update Fast-Path DDoS mitigation rules on the fly. Application-level decisions are instantaneously reflected in BPF maps, offloading packet drops to Cycle 0 of the network driver with zero user-space overhead.
* **Silent TLS Tarpitting via `SO_LINGER(0)`:** When a TLS/mTLS handshake fails or is identified as malicious, XDP silently drops (`XDP_DROP`) the `TCP RST` packet generated by the system using `SO_LINGER(0)`. The attacker is trapped in a socket timeout (*tarpitting*), while OpenBSD and BoxA free up resources in sub-microseconds.
* **Zero-Latency State Migration & Immunity for Authenticated Users:** Seamless transition of sessions from the pre-authentication staging area (`map_unauth`) to the hardware fast-path (`map_session`) while maintaining TCP sequence tracking (`seq_expected`). Validated sessions are exempted from generic Fast-Path Anti-DDoS rules and protected by RFC 793 in-window validation, ensuring maximum throughput and zero false positives for legitimate users during active volumetric attacks.
* **Active Teardown & Event-Driven Garbage Collection:** Deterministic memory cleanup triggered by event sources (*single source of truth*) sent from both OpenBSD (via internal UDP) and the local Gatekeeper. This eliminates GC scanning latency, leaving the user-space GC daemon purely as a fault-tolerant safety net for abnormal disconnects over unstable networks.

---

### 🏎️ The Ubiquitous Guardian: XDP Layer (Hosted in Box A)
The XDP framework is physically hosted within **Box A (Linux)**, but its filtering activities are isolated from the rest of the operating system and the AI engines.
* **Isolation & Driver Execution:** XDP operates at the Network Interface Card (NIC) driver level—intercepting packets before they reach the Linux network stack—and executes its tasks by segregating processing onto dedicated CPU hardware cores. This ensures that network attacks or traffic spikes do not steal computing resources from AI inference.
* **Fast-Path Packet Redirection (`XDP_REDIRECT`):** Validated packets intended for OpenBSD (Box B) bypass the standard Linux kernel network stack and are directly forwarded at the driver/NIC level using **`XDP_REDIRECT`** to the target interface.
* **Symmetric Ingress Validation:** Ingress requests from the internet undergo continuous header and protocol validation through XDP and OpenBSD `pf` before being delivered to the processing layers.
* **Dynamic, Ecosystem-Driven DDoS Policies:** XDP applies and updates its DDoS mitigation and rate-limiting (packets-per-second) policies by absorbing real-time instructions and telemetry from the entire ecosystem (semantic alerts from Box A's Gatekeeper and coordinated reactive actions from Box B).
* **BGP / RTBH (Remote Triggered Black Hole):** The dynamic blackhole mechanism leverages routing daemon interactions: Box B manages external BGP sessions to the upstream datacenter via `OpenBGPD`, while the `Bird` daemon on Box A receives discard routes via BGP from Box B. This allows XDP to read the routing tables and immediately drop traffic to and from invalid networks or malicious addresses.
* **IPv6 Deterministic NDP Handling:** To avoid Linux Neighbor Cache desynchronization, the filter delegates ICMPv6 Neighbor Discovery Protocol (NDP) handling to the Linux network stack via `XDP_PASS`. The XDP parser strictly permits ICMPv6 Types 133 (RS), 134 (RA), 135 (NS), and 136 (NA) under validated conditions (Link-Local Unicast `fe80::/10`, Multicast `ff02::/16`, Duplicate Address Detection, and assigned subnets).
* **Software Architecture:**
  - **Kernel Space:** Code written in **Restricted C** for ultra-low-level packet processing (eBPF).
  - **User Space Control:** A management program written in **C++**.

### 🔲 BOX A: The Inference & Core Layer (Linux)
Hosts the isolated XDP infrastructure, the heavy computational environment, and the deep semantic analysis logic.
* **Dual AI Engine Architecture:** 
  1. **Main AI Engine:** Powered by **mistral.rs** for high-performance, memory-safe, and optimized AI inference serving the end application.
  2. **Secondary Small AI Engine:** A lightweight, specialized model controlled by the Gatekeeper, dedicated exclusively to input analysis (e.g., advanced token counting, classification of malicious prompts, or bad input).
* **Gatekeeper:** A software daemon written in Rust that orchestrates Box A, manages the small check-engine to validate requests, and actively instructs the XDP framework to swiftly mitigate hosts attempting semantic attacks at the source.
* **Policy-Based Update Routing:** All system traffic (updates, telemetry) is explicitly bound via Policy-Based Routing (PBR) or dedicated interfaces to egress exclusively through Box B via the dedicated Optical Access Line (FTTx).

### 🔲 BOX B: The Shield & AI Secure Gateway (OpenBSD)
Represents the security perimeter exposed to the external network, operating behind the XDP filtering layer.
* **Operating System:** Native **OpenBSD**, focused on pure infrastructure security and stateful inspection without hosting heavy AI models (leveraging native primitives like `pledge`/`unveil` and `pf`).
* **Active L7 Teardown via UDP Control Channel:** When the AI Secure Gateway detects L7 anomalies or policy violations, it transmits a high-priority UDP control message to Box A's LAN interface. XDP intercepts this message, atomically purges the session from `map_session`/`map_handshake`, adds the client to `map_blacklist`, and immediately drops the UDP command packet (`XDP_DROP`).
* **Silent Tarpit Defense (Slowloris Mitigation):** When OpenBSD terminates silent/hostile sockets (e.g., via `SO_LINGER(0)`), the generated `TCP RST` packets are intercepted on Box A's LAN interface and silently dropped (`XDP_DROP`). This traps the attacker in a resource-draining timeout loop while freeing OpenBSD resources instantly.
* **AI Secure Gateway:** A deterministic, memory-safe daemon written in Rust running with restricted privileges (`pledge("stdio rpath inet", NULL)`). It performs deep protocol validation and collaborates with Box A's XDP layer via the dedicated UDP Teardown protocol.
* **On-Demand Egress Whitelisting (`pf` Anchors):** Maintains a zero-trust default posture for outbound traffic. During maintenance cycles, temporary mirror rules are loaded dynamically into dedicated `pf` anchors (`anchor "updates"`) and flushed immediately upon completion.
---

### 🔄 Dynamic On-Demand Egress Routing (`pf` Anchors)
To avoid tracking shifting CDN mirror IPs inside eBPF maps on Box A, outbound system update traffic (e.g., `dnf update`) is offloaded entirely to a dedicated Optical Access Line (FTTx interface) managed dynamically by OpenBSD `pf` anchors:

```text
┌──────────────────────────────────────────────────────────────┐
│                     BOX A (Rocky Linux)                                                               │
│  1. dnf triggers update request                                                                       │
│  2. Policy-Based Routing (PBR) routes traffic through                                                 │
│     dedicated Optical Access Line (FTTx) directly to Box B                                            │
└──────────────────────────────┬───────────────────────────────┘
                               │ Isolated Optical Access Line / FTTx
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                     BOX B (OpenBSD / PF)                                                              │
│  3. Daemon dynamically loads mirror IP rules                                                                 │
│     into PF anchor: `anchor "updates"`                                                                │
│  4. Stateful PF Inspection evaluates anchor rules; flushes                                            │
│     anchor immediately upon update completion                                                         │
└──────────────────────────────┴───────────────────────────────┘
```

1. **Deterministic Dedicated Offload (Box A):** System maintenance traffic bypasses XDP Map dynamic lookups entirely and is directed through a dedicated Optical Access interface connected directly to Box B.
2. **Dynamic On-Demand Whitelisting (Box B / OpenBSD):** Egress access is blocked by default. When maintenance is scheduled, ephemeral rules and temporary mirror IP tables are dynamically injected into a reserved `pf` anchor (`anchor "updates"`). Once the update finishes, the anchor is completely flushed, leaving zero open outbound surface.

---

## 🔬 Architectural Roadmap & Future Hardening Ideas
*The following items are design goals and hardening concepts intended for high-assurance hardware setups as the project evolves past the single-PC simulation phase.*

### 🛡️ Box A Hardening Ideas: Native SELinux & XFS (Bare-Metal)
To minimize host attack surface and eliminate container-escape zero-days:
* **SELinux (Enforcing Mode):** Enforces strict Mandatory Access Control (MAC) policies over local daemons, isolating the XDP control program and inference engines.
* **XFS File System:** Chosen for high-performance I/O, rigid permission masks, and native POSIX ACL enforcement.
* **Bare-Metal Execution Concept:** Eliminates container runtime dependencies (Docker/Podman), removing unnecessary kernel surface exposure and overhead.

### 🔒 Box B Sandboxing: OpenBSD `pledge()`
The Rust-based **AI Secure Gateway** running on Box B uses OpenBSD's native security primitives for extreme process isolation:
* **Syscall Restricting (`pledge`):** The daemon locks down its execution environment (e.g., `pledge("stdio rpath inet", NULL)`), revoking execution capabilities by omitting the `"exec"` promise and restricting unneeded kernel interfaces.

---

## ⚡ Technical Advantages & Performance Metrics

### 🔲 Impact on Latency
Through the use of XDP technology and optimized virtualized or physical interconnections:
* **Zero Overhead from Box B:** Box B does not introduce perceptible latency because it performs tasks OpenBSD is natively optimized for (packet parsing, state management, and filtering).
* **No Volumetric Filtering Overhead on Box A:** Having eliminated L3/L4 DDoS attack attempts on Box B or instantly discarded them via XDP on Box A, the interconnection line handles only clean, legitimate, and pre-validated traffic.

### 🔲 Update Reduction Profile (Kernel Security)
Since Box A is not directly exposed to the Internet and only communicates with the specific IP/MAC of Box B, the network attack surface on the Linux kernel is minimized.
* **Reduced Patching Cycle:** It is not necessary to reboot or update the Linux kernel of Box A for every public network vulnerability. Reboots of Box A (which are impactful due to reloading large AI models into VRAM) can be planned on long-term schedules, leaving Box B (OpenBSD) the task of undergoing frequent security updates quickly and transparently.

### 🔲 Resource Separation (CPU vs GPU)
* **Box A (GPU-Bound / Compute-Bound):** Dedicates its CPUs solely to data offloading over the PCIe/VRAM BUS and its GPUs 100% to executing tensors and language models (`mistral.rs`), without host clock cycles being stolen by network interrupts or packet analysis.
* **Box B (CPU-Bound / I/O-Bound):** Handles traffic parsing, TLS termination, authentication, network state management, and traffic sanitization to and from the Gatekeeper.

---

## 🏗️ Conceived Technology Stack
* **Network & Filtering Layer (Box A):** XDP Driver Layer (**Restricted C**), XDP User Space Daemon (**C++**).
* **Box A (Inference & Input Check):** Linux Kernel, Policy-Based Routing (PBR), SELinux + Seccomp + XFS, Gatekeeper (**Rust**), Small Check-Engine, Main AI Engine (**mistral.rs**).
* **Box B (Pure Security):** OpenBSD Kernel, `pf` firewall with dynamic anchors (`anchor "updates"`), AI Secure Gateway (Deterministic **Rust** with `pledge`/`unveil`).

---

## 📄 Licensing & Commercial Terms

Copyright (c) 2026 Marco Giuseppe Spiga (<workwheat09@gmail.com>).

### 1. Architectural Specification & Documentation
The conceptual architecture, threat models, network flows, and design specifications in this repository are licensed under the **[Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0)](https://creativecommons.org/licenses/by-nc/4.0/)**.

* **Educational & Personal Use:** Completely free to study, share, and adapt for non-commercial research with proper attribution to the author.
* **Non-Commercial Restriction:** May not be used for commercial product implementations, paid services, or proprietary deployments without explicit authorization.

### 2. Source Code & Reference Implementations
All software components, eBPF/XDP drivers (Restricted C), OpenBSD integration scripts, and user-space control daemons (C++/Rust) are licensed under the **[GNU General Public License v3.0 (GPLv3)](https://www.gnu.org/licenses/gpl-3.0.html)**.

* **Open-Source Reciprocity:** Any party modifying or building upon this software must keep their derivative works fully open-source under GPLv3.

### 💼 Commercial Licensing & Consulting Inquiries
For commercial licensing, enterprise deployment rights, proprietary integrations, or consulting opportunities, please contact the author directly:

* **Author:** Marco Giuseppe Spiga
* **Email:** [workwheat09@gmail.com](mailto:workwheat09@gmail.com)

---
*Extended security modeling, technical documentation formatting, and diagram layout refined in collaboration with **Gemini** (Google AI Systems).*
