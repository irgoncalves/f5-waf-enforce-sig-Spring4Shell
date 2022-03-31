# f5-waf-enforce-sig-Spring4Shell
This enforces signatures for the vulnerabilities Spring Framework (Spring4Shell) and Spring Cloud vulnerabilities CVE-2022-22965, CVE-2022-22950, and CVE-2022-22963 across all policies on a BIG-IP ASM device.

# Overview

This script enforces all signatures present in the list below related to the vulnerabilities Spring4Shell and Spring Cloud across all policies in blocking mode in the Adv. WAF/ASM.

For the current list of attack signatures, check the following article:
https://support.f5.com/csp/article/K19026212

This was tested on BIG-IP ASM/Adv.WAF v15.x but I expect this to work in v13/v14/v16 as well.

## Prerequisites

Python 3.7+

The host machine needs to have connection to the BIG-IP management interface.

# How to Use

```
usage: f5-waf-enforce-sig-Spring4Shell device

positional arguments:
  device      File with IP adrresses of the target BIG-IP devices separated by line
