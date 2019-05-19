# ddosd-p4
This is the P4 description of a real-time in-network DDoS attack detection mechanism as proposed within the paper "Offloading Real-time DDoS Attack Detection to Programmable Data Planes" (IM 2019).
The target is the `simple_switch` variation of the P4 behavioral model software reference implementation (bmv2).
Since production performance has not been a design goal of bmv2, this is a proof of concept in terms of data-plane implementation feasibility conforming to P4 primitives.
A functional equivalent C++ implementation is available at [ddosd-cpp](https://github.com/aclapolli/ddosd-cpp) enabling thorough evaluation.

## Getting Started

These instructions will guide you to run the detection mechanism on the target switch.
We recommend using an Ubuntu 16.04 virtual machine.

### Prerequisites
We have extended both the behavioral model and the P4 reference compiler (p4c) to support hashing as required by our count sketch.
First, clone our forked repositories and follow the installation guidelines within:

- [behavioral-model](https://github.com/aclapolli/behavioral-model)
- [p4c](https://github.com/aclapolli/p4c)

### Building
Ensure that the `p4c` binary is within your `$PATH` and run:
```
git clone https://github.com/aclapolli/ddosd-p4.git
cd ddosd-p4
make
```

This process builds the P4 program into `./build/ddosd.json`

### Running

#### Quick Start
For a quick test, you may execute:
```
./scripts/run.sh
```
This script initiates an instance of the target switch associated to virtual network interfaces.
It configures the switch to forward every IPv4 packet to `veth2`.
It also sets up the detection mechanism with m = 2<sup>18</sup>, &#945; = 0.078125, k = 3.5, and a training phase containing 250 observation windows.
You may change these parameters at runtime using the `simple_switch_CLI` tool (see [control_rules.txt](scripts/control_rules.txt) for examples).

We recommend using the `veth0` interface to input packets to the detection mechanism.
The last package of every observation window will be forwarded to `veth4` containing the following custom header:
```
// EtherType 0x6605
header ddosd_t {
    bit<32> packet_num;    // The packet number within the observation window (always equal to m)
    bit<32> src_entropy;   // The last observation window entropy of source IP addresses (scaled by 2^4)
    bit<32> src_ewma;      // The current EWMA for the entropy of source IP address (scaled by 2^18)
    bit<32> src_ewmmd;     // The current EWMMD for the entropy of source IP address (scaled by 2^18)
    bit<32> dst_entropy;   // The last observation window entropy of destination IP addresses (scaled by 2^4)
    bit<32> dst_ewma;      // The current EWMA for the entropy of destination IP address (scaled by 2^18)
    bit<32> dst_ewmmd;     // The current EWMMD for the entropy of destination IP address (scaled by 2^18)
    bit<8> alarm;          // It is set to 0x01 to indicate the detection of a DDoS attack
    bit<16> ether_type;    // Indicates the following header EtherType
}
```

#### Custom Deployment
Ensure that both the `simple_switch` and the `simple_switch_CLI` binaries are within your `$PATH` and run (with custom options):
```
simple_switch [options] ./build/ddosd.json
```
Don't forget to install rules via the `simple_switch_CLI` tool to parameterize the detection mechanism and populate the LPM lookup table used for entropy estimation (see [control_rules.txt](scripts/control_rules.txt) for examples).

## Troubleshooting
There is a known bug in Ubuntu's 16.04 LLVM 3.8 packaging which may cause an [error](https://stackoverflow.com/questions/38171543/error-when-using-cmake-with-llvm) while executing `cmake`.
For dealing with this problem, we suggest upgrading to the LLVM 3.9 version executing the following commands:
```
sudo apt-get remove llvm
sudo apt-get autoremove
sudo apt-get install llvm-3.9
```

## License
This repository is licensed under the GNU General Public License v3.0 (check [LICENSE](LICENSE) for details).
