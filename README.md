# EDRity - Volatility Contest 2023 Writeup

## Motiviation

As I stated in the email, I wanted to stretch what is possible with a python memory analysis framework.
So, I combined my love for low-level development and drivers with the Forensic itch and created two submissions integrated to one, EDRity.

## What is EDRity?

EDRity is a live (but can be used on a memory dump) memory scanning tool that iterates over your process VADs (/proc/maps for windows), finds RXNi executables, dumps them and polls VirusTotal's engines for an analysis.

## Why EDRity should win the contest

I believe EDRity is a new concept, that can stretch what is possible as forensic experts. I think with the right minds, we can use our memory analysis expertise to add on to EDRity and create something big.
That said, the creation of EDRity and specifically the winpmem memory layer, made me dive deep in volatility's inner engine and discover new stuff about it (which is what the contest is all about, I believe)

## Usage

* Install the python package ```virustotal_python```
* Download the winpmem kernel driver from the [github repo](https://github.com/Velocidex/WinPmem/releases/tag/v4.0.rc1) and run with ```winpmem...exe -l``` from an administrator command prompt
* Create a VirusTotal user and copy your api key
* Run my plugin using ```python vol.py -f winpmem://pmem windows.edrity --api-key=YOUR_API_KEY
* Profit!

## Future Plans

* Add shellcode extraction mechanisms
* Add basic analysis at home, offline (EDRity on prem :D)
* Add an agent, windows exectuable, with volatility packed in it that runs EDRity in a loop together with other great plugins