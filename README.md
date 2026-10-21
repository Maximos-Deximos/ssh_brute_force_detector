# ssh_brute_force_detector
A python script that logs and monitors SSH attempts
with entries showing source IP, username attempted, and authentication status

## What does the script have:

The ability to read log files and extract failed SSH login attempts, including source IP
addresses and timestamps.

A brute force pattern detection by tracking failed login attempts per source IP over 
time windows (e.g., 5 failed attempts in 600 seconds indicates an attack). with configurable 
thresholds for what constitutes an attack, distinguishing between user mistakes and actual brute
force attacks.

An IP reputation tracking system by maintaining a database of known-good IPs (internal networks,
remote offices, trusted partners) that are excluded from blocking, and a list of known-bad IPs
that have shown attack behavior. This functionality preventing false
positives where legitimate users get blocked after mistyping passwords a few times.

# Attention

This script has not yet been tested agains't a live brute force attack, its funcionality and features are currently being tested via static and fictional logs

## Planned features:

- Automatic firewall rule addition
- Alerting and logging functionality
