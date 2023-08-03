# Slither design patterns plugin

Slither is a static analysis tool for Solidity smart contracts.

This plugin implements detectors for the following design patterns:
- Guard check pattern
- Facade pattern
- Emergency stop pattern
- Oracle pattern

## How to use

### Prerequisites

- Python 3.8 or higher
- Slither 0.9.3

### Installation

Usage of virtual environment is recommended.

- Clone this repository
- Navigate to the root of the repository
- Run `python3 setup.py develop`

### Usage

Once the plugin is installed, Slither will automatically use all of the detectors implemented in this plugin.

Alternatively, you can use the `--detect` flag to only run specific detector. For example `slither Contract.sol --detect guard-check` will only run the guard check pattern detector on file `Contract.sol`.