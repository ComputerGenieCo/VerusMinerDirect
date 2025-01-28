[![CodeQL](https://github.com/ComputerGenieCo/VerusMinerDirect/actions/workflows/codeql.yml/badge.svg)](https://github.com/ComputerGenieCo/VerusMinerDirect/actions/workflows/codeql.yml)
[![Issues](https://img.shields.io/github/issues-raw/ComputerGenieCo/VerusMinerDirect)](https://github.com/ComputerGenieCo/VerusMinerDirect/issues)
[![PRs](https://img.shields.io/github/issues-pr-raw/ComputerGenieCo/VerusMinerDirect)](https://github.com/ComputerGenieCo/VerusMinerDirect/pulls)
[![Commits](https://img.shields.io/github/commit-activity/m/ComputerGenieCo/VerusMinerDirect)](https://github.com/ComputerGenieCo/VerusMinerDirect/commits/master)
[![Contributors](https://img.shields.io/github/contributors/ComputerGenieCo/VerusMinerDirect)](https://github.com/ComputerGenieCo/VerusMinerDirect/graphs/contributors)
[![Last Commit](https://img.shields.io/github/last-commit/ComputerGenieCo/VerusMinerDirect)](https://github.com/ComputerGenieCo/VerusMinerDirect/graphs/commit-activity)
# VerusMinerDirect

Based on ccminer-verus written by [Oink70](https://github.com/Oink70) and [monkins1010](https://github.com/monkins1010)  
which was based on  
ccminer written by [Tanguy Pruvot](https://github.com/tpruvot/ccminer)  
which was based on  
"Christian Buchner's &amp; Christian H.'s CUDA project, no more active on github since 2014."  

Which is a lot of words to say "a cobbled pile of bovine excrement" (see, Mike, I *can* use 'G'-rated words, I'm just not going to when demanded).

## Development speed

I'm an old VB coder working on this project in my spare time; if you want it to happen faster, encourage those in the Verus "community" with ccminer and/or C++ experience (pretty much those that should have done this years ago) to get involved with a project that would benefit the Verus community.

## Purpose

Eventually, this will be an optimized VerusCoin miner that mines directly to the user's daemon.  
That'll happen after I remove all of the extraneous bull shit that shouldn't even be in it.

### What is or is going to be removed?
* All algos other than verushash
* Multi-pool options
* All the bull shit copy/pasted from Verus daemon "just because" (ugh)
* All wasteful junk spanning a decade of cobbling ccminer together
* API
* Support for CPUs without AES/AVX
* Anything else I can think of or come across that shouldn't be in a Verus miner