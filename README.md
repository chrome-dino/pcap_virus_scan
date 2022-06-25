# Pcap Virus Scan 

The Pcap Virus Scanner is a tool used to speed up the process involved in analyzing pcap files for malware. It does this by combining the power of Wireshark's command line equivalent (tshark) with both offline and online virus scanning tools. The first thing the tool does is automatically extract downloaded objects based on a specified protocol. It then analyzes each of the exported objects with either virus total or a set of yara rules. If the virus total mode is selected an api key for virus total is required.


## Table of Contents
* <a href="#key-features">Key Features</a></br>
* <a href="#installation">Installation</a></br>
* <a href="#how-to-use">How To Use</a> </br>
* <a href="#notes">Notes</a></br>
* <a href="#license">License</a>


## Key Features

* Automatically extract downloaded objects from a pcap file
* Submit files to virus total and build a report on the trustworthiness of each file
* Can be used completely offline with the use of yara rules


## Installation

```bash
# Clone this repository
$ git clone https://github.com/chrome-dino/pcap_virus_scan.git

# From the directory containing your git projects
$ pip install -e pcap_virus_scan
```

Uses the following python libraries:
* virus_total_apis
* hashlib
* os
* yara
* sys
* argparse

## How To Use

### Help Menu

```bash
usage: __main__.py [-h] -f FILE -m MODE (-k KEY | -r RULES) [-y | --yara | --no-yara]
                   [-x | --executables | --no-executables] [-v | --virus_total | --no-virus_total]

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  pcap file to be analyzed
  -m MODE, --mode MODE  protocol to export objects from. Choose from http, smb, tftp, imf
  -k KEY, --key KEY     virus total api key
  -r RULES, --rules RULES
                        yara rules file
  -y, --yara, --no-yara
                        scan objects with yara
  -x, --executables, --no-executables
                        only scan for executable files
  -v, --virus_total, --no-virus_total
                        submit objects to virus tota
```

### Video
* https://youtu.be/vI9GrCCFhMQ

### Examples

```bash
# extract http objects and submit them to virus total. Only evaluates executable objects
$ py -m pcap_virus_scan -f file.pcap -v -k API_KEY -m http -x

# extract smb objects and analyze them with yara
$ py -m pcap_virus_scan -f file.pcap -y -r path_to_yara_rules -m smb
```


## Notes

* Tested on python 3.10.4


## License

MIT
