# ACE:  Approximate Concrete Execution

This repository contains artifacts from the research and development of approximate concrete execution (ACE), a binary analysis technique used to fingerprint and discover software components (i.e., libraries and functions) compiled into software binaries (especially those found on serverless cloud systems). Most of these artifacts take the form of Jupyter notebooks, which contain code, raw results, and notes made by ACE's inventors. 

Because ACE was developed over several years, statements or results recorded in earlier notebooks may be outdated. Please see our paper (cited below) for our most-current understanding of this technique.

Please note that ACE is covered by [U.S. Patent 11,074,055](https://perma.cc/S6RD-4CQS).

## The Paper
We strongly recommend reading our paper published at the 2020 Workshop on Serverless Computing (WoSC'20) before diving into this repo.

When using or referencing this work, please cite the following paper.

> Anthony Byrne, Shripad Nadgowda, and Ayse K. Coskun. 2020. ACE: Just-in-time Serverless Software Component Discovery Through Approximate Concrete Execution. In *Workshop on Serverless Computing (WoSC ’20), December 7–11, 2020, Delft, Netherlands*. ACM, New York, NY, USA, 6 pages. https://doi.org/10.1145/3429880.3430098

An open-access version of our paper is accessible from the ["publications" section of the PEACLab website](https://www.bu.edu/peaclab/publications).

## The Artifacts
The artifacts in this repository are organized into directories as follows.

 * `toy-examples`: A notebook demonstrating the basics of ACE. This is a great place to start after reading our WoSC'20 paper.
 * `lib-identify`: Notebooks documenting the origins of the ACE project, which was originally focused on finding ways of identifying which libraries are used in a (statically-linked) binary. These notebooks contain very early-stage commentary and results that may no longer be accurate (see disclaimer above).
 * `cve-crossarch`: Notebooks and Python helper scripts exploring applications of ACE to the problem of finding software vulnerabilities (CVEs), including a focus on the ability to detect vulnerabilities across architectures (i.e., x86_64 and ARMv8 (64bit)). Most of the results in our WoSC'20 paper come from these notebooks.
 * `res`: "Static" resources, like source code for test binaries.
 * `util`: Utility scripts. Mainly contains the "authoritative" version of the ACE approximate virtual machine (aVM).