# Implementation notes

The network_analysis module builds a deterministic graph from relationships already attached to normalized resources. Edges retain their source attribute and provenance. Missing and ambiguous targets are not invented.

Public-ingress assessment requires explicit evidence for public addressing, a route to an internet gateway, a matching ingress rule, known attached security groups, and a network ACL that permits the path. A missing signal is unknown, not isolated. The helper does not yet derive all signals automatically from raw EC2/ELB APIs and is not a complete packet-level reachability engine.
