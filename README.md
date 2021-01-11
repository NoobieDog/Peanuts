Peanuts V3.9                                  
                                    
========

Release Date: 11/01/2021

UPDATED FOR PYTHON 3

Peanuts is a free and open source wifi tracking tool. Based on the SensePosts Snoopy-NG project that is now closed.<br />

Less dependencies, less overhead, less complications<br />

This tool is featured in the film "All the devils men", Directed by Matthew Hope

	https://www.imdb.com/title/tt6012244/

NOTE: Im not sure how long i will supprot this project as its a slowly dying method, if i get time to work on it i will :D<br />

**** FOR EDUCATIONAL USE! Use at your own risk. **** <br />

+ Tested on: Linux 3.2.6 Ubuntu/Debian (Kali)/Rpi<br />

## Installation:

### Dependencies:

#### Required:

```bash
pip install -r requirements.txt
```

#### Installing from Source
 
```bash
git clone https://github.com/noobiedog/peanuts/
cd peanuts
pip install -r requirements.txt
apt-get install python-gps bluetooth bluez python-bluez
```

#### To start GPS in kali/Ubuntu (in a separate terminal window)

```bash
service gps start
gpsd -D 5 -N -n /dev/ttyUSB0
```
##  Sample commands

#### Simple

``` bash
python peanuts.py -i wlan0 -l Home -o Capture1.csv
```

-i Interface (Doesnt matter if not in monitor mode, the program will do it)<br />
-l location or OP name, whatever you want to identify this capture<br />
-o Output file name for the CSV<br />

#### Advanced

``` bash
python peanuts.py -i wlan0mon -l target1 -o unknown.csv -a true -m http://localhost:8080/api/data -g true

```

-i Interface (Doesn't matter if not in monitor mode, the program will do it)<br />
-l location or OP name, whatever you want to identify this capture<br />
-a Include Access Points too in the results<br />
-g Get GPS location of your device (Not tested with Nethunter, yet. Also will need GPSD running)<br />
-o Output file name for the CSV<br />
-m Send Map data to JSON endpoint

## Lets See it in Action

[![ASCIICinema](http://i.imgur.com/saR06iC.png)](https://asciinema.org/a/4lf58gw5psnik38wb4umud5r0)

Happy Hacking

NOTE: This method of WIFI tracking is slowly dying with the new IOS 10 Updates and Android updates.

https://gist.github.com/computerality/3e0bc104cd216bf0f03f8d3aa8fbf081 line 176
