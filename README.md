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
Represents the security perimeter exposed to the external network, filtered by XDP. OpenBSD receives and exchanges network traffic passing through the XDP layer.
* **Operating System:** Native **OpenBSD**, focused on pure infrastructure security without any AI components (process isolation via `pledge`/`unveil` and the `pf` firewall).
* **Active Kernel-Level Reaction:** When threats or protocol anomalies are identified, the OpenBSD kernel performs low-level intervention by transmitting `TCP RST` (Reset) packets across Box A's internal interface, triggering XDP to promptly terminate the offending session. Through this mechanism, the OpenBSD kernel dynamically leverages XDP to enhance overall DDoS control.
* **AI Secure Gateway:** A deterministic, memory-safe proxy application written in Rust that validates protocols and analyzes semantic flows. It works in synergy with the OpenBSD kernel and communicates with Box A via custom `TCP RST`/Rust packets to instruct XDP to drop hostile hosts' packets directly at the hardware source.
* **On-Demand Egress Whitelisting (`pf` Anchors):** Maintains a zero-trust default stance for egress traffic. When updates are triggered, ephemeral mirror whitelists are loaded dynamically into specialized `pf` anchors (e.g., `anchor "updates"`) on demand and flushed immediately upon completion.

---

### 🔄 Dynamic On-Demand Egress Routing (`pf` Anchors)
To avoid tracking shifting CDN mirror IPs inside eBPF maps on Box A, outbound system update traffic (e.g., `dnf update`) is offloaded entirely to a dedicated Optical Access Line (FTTx interface) managed dynamically by OpenBSD `pf` anchors:

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
│  3. Gatekeeper/Daemon dynamically loads mirror IP rules                                               │
│     into PF anchor: `anchor "updates"`                                                                │
│  4. Stateful PF Inspection evaluates anchor rules; flushes                                            │
│     anchor immediately upon update completion                                                         │
└──────────────────────────────┴───────────────────────────────┘

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
* **Box A (Inference & Input Check):** Linux Kernel, Policy-Based Routing (PBR), SELinux + XFS, Gatekeeper (**Rust**), Small Check-Engine, Main AI Engine (**mistral.rs**).
* **Box B (Pure Security):** OpenBSD Kernel (Active `TCP RST` generation), `pf` firewall with dynamic anchors (`anchor "updates"`), AI Secure Gateway (Deterministic **Rust** with `pledge`/`unveil`).

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
