# Quazaa-Security-Library



The Quazaa Security Library implements a security manager for filesharing clients. It allows creating and managing security rules and checking content against them.

The different currently supported rule types are:
* Single IP rules
* IP range rules
* Country rules (can be disabled at compile time if undesired)
* Hash rules
* Keyword based rules (match any/all)
* Reguler expression content rules
* User agent rules

Features
=========
* Support for banning (or banning all but) single IPs, IP ranges or entire countries.
* Support for filtering network search hits by their content (hashes, file names, regular expressions).
* Support for checking client names against lists of known fake clients.
* Performance is achieved by using hashtables for IP, country and hash lookup, binary search for IP ranges and fast vector iterations for all other rule types.
* Designed to keep GUI and core implementation separeted.
