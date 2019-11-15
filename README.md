# CAAC - CAA record checker

This little tools lets you check / create a CAA Record for one domain or check several domains if a records exists. 
It creates records for following DNS:


- Generic - For Google Cloud DNS, Route 53, DNSimple, and other hosted DNS services
- Standard Zone File - For BIND ≥9.9.6, PowerDNS ≥4.0.0, NSD ≥4.0.1, Knot DNS ≥2.2.0
- Legacy Zone File (RFC 3597 Syntax) - For BIND <9.9.6, NSD <4.0.1, Windows Server 2016
- dnsmasq


## Getting Started

Clone the repo with 

```
git clone https://github.com/joelgun-xyz/caac.git
```

### Prerequisites

This tool runs on Python3. 

### Installing

You need to install a couple of libs from the requirements.txt


```
PyYAML==5.1.2
dnspython==1.16.0
tqdm==4.31.1
Click==7.0
click-plugins==1.0.4
requests==2.22.0
```

Change in the cloned project directory and run following command to install them all: 

```
pip3 install -r requirements.txt
```


## Running the script

You can check for / create a CAA record with:

```
python3 caac.py -d example.com
```


You can check several domains for CAA records with: 

```
python3 caac.py -bd example.com,example2.com,example.com
```

### Output

Sample CAA check output:


```
[ +++ ] Found an entry for "raiffi.ch"!

raiffi.ch. 0 iodef "mailto:ca@raiffi.ch" 
raiffi.ch. 0 issue "amazon.com" 
raiffi.ch. 0 issue "digicert.com" 
raiffi.ch. 0 issue "quovadisglobal.com" 
```

If there is no:


```
python3 caac.py -d vqb.ch

[ +++ ] There was no CAA Record!

Do you want to create one? [y/N]: 

```

## Authors

* **joelgun** - *Initial work* - up(https://twitter.com/joelgun

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* CAA helper from SSLMate 

