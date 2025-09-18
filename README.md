
## Project Overview

This project provides tools for decrypting Lightning Network packets and analyzing node handshakes.

### Structure

- **decryptor folder**: Contains the Brontide decryptor program, which extracts and decrypts Lightning Network messages from captured network traffic. See the README inside for usage and implementation details.
- **modified-lnd folder**: Contains a custom version of the LND node. This node has been modified to log handshake data (salt and cipher keys) during the initial connection setup. These logs are essential for the decryptor to reconstruct session keys and decrypt traffic.

### Handshake Extraction

The modified LND node writes handshake information (including salt and cipher keys) directly to its log files. The user must manually access these logs and provide them as input to the decryptor program. The decryptor's README explains how to supply and read this data for accurate decryption of Lightning messages.

### Network Simulation and Packet Capture

To simulate a Lightning Network environment and capture packets, a custom version of the Polar tool from my GitHub is used. This fork adds additional functionality for network tracking inside the simulated Lightning Network, making it easier to monitor and analyze node interactions. Polar allows you to easily spin up Lightning nodes and networks for testing and analysis.

### Building the Modified LND Docker Image

To build the modified LND image for use in Polar or other simulations, run:

```sh
docker build -v -f Dockerfile.polar .
```

This will create a Docker image with handshake logging enabled, suitable for Lightning Network node emulation and traffic capture.

---
For more details on decryptor usage, see the documentation in the `decryptor` folder.
