# Project: Distributed Network Routing & Anomaly Simulator

## Project Overview
This project is a distributed network simulator designed to demonstrate backend systems architecture, process management, and custom networking protocols. It consists of two main layers:
1.  **Data Plane (C++)**: High-performance network nodes communicating via UDP sockets. Each node is an independent Linux process that manages its own memory, lock-free queues, and routing tables.
2.  **Control Plane (Python)**: An orchestration and analysis layer that configures the network topology, manages processes, monitors traffic anomalies (e.g., DDoS), and recalculates optimal routing flows.

## AI Assistant Role & Guidelines
* **Learning Over Output**: Act as a senior systems engineer. Your primary goal is to help me understand the theoretical concepts and architectural decisions. Always explain *why* a specific OS-level system call (e.g., `fork`, `exec`), networking protocol, or memory management technique is chosen before generating the code.
* **Systems Programming Focus**: Strictly adhere to modern backend architecture practices. Avoid web development paradigms. Focus on multi-threading, synchronization, IPC (Inter-Process Communication), and raw socket programming.
* **No Black Boxes**: Do not use heavy external frameworks for the core logic. Networking in C++ must be done using raw standard libraries (e.g., `<sys/socket.h>`, `<netinet/in.h>`).

## Coding Standards

### C++ (Core Network Nodes)
* Use modern C++ (C++17 or higher).
* Enforce strict memory management. Prevent memory leaks by utilizing smart pointers (`std::unique_ptr`, `std::shared_ptr`) where appropriate, but prefer stack allocation for low-latency packet processing.
* Use standard POSIX libraries for networking and threading (`<pthread.h>` or `<thread>`).
* Handle all system call errors gracefully (e.g., checking return values of `socket()`, `bind()`, `recvfrom()`).
* Keep dependencies minimal. 

### Python (Control Plane & Orchestration)
* Use Python 3.10+.
* Adhere to PEP 8 standards. Use Type Hints strictly for all function signatures.
* Keep the orchestration modular. Separate the logic for process management, metrics collection, and anomaly detection.

## Build and Execution Commands
* **C++ Build**: `g++ -std=c++17 -Wall -Wextra -pthread src/node.cpp -o bin/node`
* **Python Setup**: `python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt`
* **Run Control Plane**: `python3 control_plane/main.py`
* **Clean Build**: `rm -rf bin/*`

## Project Structure (Target)
* `/src`: C++ source files (node logic, packet structures, UDP handling).
* `/control_plane`: Python scripts (topology parser, anomaly detection, dashboard).
* `/config`: JSON files defining network topologies.
* `/bin`: Compiled C++ executables.

## Version Control Guidelines
* Act as the strict maintainer of this repository.
* Commit changes frequently, ideally after every logical milestone, working feature, or bug fix.
* Never commit broken code unless explicitly instructed for debugging purposes.
* Use conventional commits for all messages (e.g., `feat: added UDP listener`, `fix: resolved race condition in lock-free queue`, `refactor: extracted routing logic`).
* Provide a brief but descriptive body in the commit message explaining *why* the change was made, not just *what* was changed.