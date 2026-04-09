the goal is to have a golang single file executable that can be deployed to freebsd 14 or later systems. 

it will be a dashboard and diagnostic gui for displaying information from /dev/pf, pfctl, or other pf cli or subsystems.
i basically want a single file executable that replicates similar dashboards and functionality in opnsense or pfsense.

for example i want to be able to display blocked traffic, with optional filters
i would also like to be able to display passed traffic on various interfaces

being able to display rule counters, and rule list might be nice optional features

as a seperate feature if vnstat is installed, it would be nice to leverage it for live traffic displays and statistics
