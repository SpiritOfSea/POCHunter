# POCHunter
_@SpiritOfSea (Dzmitry Padabed)_

------
## About
**POCHunter** is a Python command line tool which aims to automate web host 
analysis. It detects used technologies and their versions via 
[Wappalyzer](https://github.com/wappalyzer/wappalyzer), searches for 
existing CVE's and corresponding Proof-of-Concepts on GitHub and ExploitDB.

_Warning: author is not responsible for any damages. You are responsible 
for your own actions. Attacking targets without prior mutual consent 
is illegal._

------
## Installation
There are few steps to prepare POCHunter.
1. Install Wappalyzer dependencies: [Git](https://git-scm.com/), 
[Node.js 14+](https://nodejs.org/), [Yarn](https://yarnpkg.com/).  

2. Clone POCHunter repository:
```
git clone https://github.com/SpiritOfSea/POCHunter
```

3. Prepare Wappalyzer:
```
cd POCHunter/api/wappalyzer
yarn install
yarn run link
```

4. Install dependencies:

```
cd ../../
pip3 install -r requrements.txt
```

5. Edit _tokens.json_ file, add your [GitHub](https://github.com/settings/tokens/) 
and [NVD](https://nvd.nist.gov/developers/api-key-requested) tokens here.
6. Run POCHunter:
```
python3 pochunter.py [arguments] <url/host>
```

------
## Usage
```
└─$ python3 pochunter.py -h                                                       
usage: python3 pochunter.py [-h] [-f] [-l] [-t] [--check] [--vulns] [--version] [--debug] [-e] [-c] [-hp] [-of FORMAT] [--nocolor] [--cvefilter CVEFILTER]
                            [--cpefilter CPEFILTER]
                            hostname

Tool to automatically find web exploits' proofs of concept

positional arguments:
  hostname

options:
  -h, --help            show this help message and exit
  -f, --force           ignore cached results
  -l, --lazy            skip unknown versions
  -t, --techs           perform only web technologies detect
  --check               check if host was cached before
  --vulns               list all CVE's for cached site
  --version             display author and version info
  --debug
  -e, --extended        disable technologies whitelisting
  -c, --cvedetails      show CVE descriptions
  -hp, --hidepocs       do not display PoC's
  -of FORMAT, --format FORMAT
                        choose output format: default, json
  --nocolor             output without color
  --cvefilter CVEFILTER
                        set minimal year for CVEs (default: 2017)
  --cpefilter CPEFILTER
                        set minimal year for CPEs (default: 2017)
                                                                  
```

-----
## Examples

- Scan _https://example.com_ in lazy mode 
(do not ask user to choose technology version) and print description of all
found CVE:

```
python3 pochunter.py https://example.com -l -c
```

- Print results of previous scan in JSON format:

```
python3 pochunter.py https://example.com -of json
```

- Rescan _https://example.com_, analyzing all technologies 
(even non-whitelisted) and looking for vulnerabilities released after 2019:

```
python3 pochunter.py https://example.com --force -e --cvefilter=2019
```