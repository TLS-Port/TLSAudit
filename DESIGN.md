# TLSAudit Design Document 

Documentation of architectural drivers and design rationales.

## Architectural drivers

* Minimal amount of dependencies so that the tool can be used out-of-the-box, without any additional installation steps on standard Linux distributions
* Modular architecture so that the tool can be easily extended to additional web servers, etc. (or the support/maintenance can be dropped for deprecated servers without affecting others)

## Architecture

To achieve modularity, TLSAudit uses the pipes-and-filters architecture. Moreover, pipes-and-filters is a natural fit to the task at hand:

1. Read Nginx configuration 
2. Parse TLS options
3. Check if there are any weak or insecure options
4. Generate and output a report

### Data structures

Dictionary D of all Nginx TLS configuration options, with keys being the individual options in a hierarchical notation `A:B:C` and values being `{secure|weak|insecure}`.

### Filters

* Parser: read Nginx configuration file (provided as argument) and extract a list L with TLS configuration options (hierarchical notation `A:B:C`)
* Checker: take L and dictionary D as input, output list R containing configuration options which are either weak or insecure
* Reporter: take R as input and generate a simple command line report (if needed, different report formats can be added later)

## Implementation

To ensure minimal amount of dependencies and maximum portability, TLSAudit is implemented as a Bash script. While TLSAudit would be easier to implement in a modern scripting language like Python, most Linux distributions come with the Bash shell pre-installed so that a Bash script can be used out-of-the-box.

### Files

* `tlsaudit.sh` is the main script
* `lib/parser.sh` contains the parser code
* `lib/checker.sh` contains the checker code
* `lib/reporter.sh` contains the reporter code
