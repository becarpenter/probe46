# probe46
This is a program to evaluate IPv6 vs IPv4 latency and drop rate using Atlas probes, viewed from any user machine with IPv4 and IPv6 access. It needs Python3, and has been tested on Windows 10 and Linux.

The Python module _ripe.atlas.cousteau_ is needed, and can be installed with _pip_ (or _apt-get_).

The program uses RIPE Atlas probes as its targets. If you don't know about that, [look here.](https://www.ripe.net/analyse/internet-measurements/ripe-atlas/) The program picks probes _at random_, so the results give some sort of average of how the Internet looks from your place.

Download `probe46.py`and store it in your favourite directory. Start it (e.g. double click in Windows, `python3 probe46.py` in Linux). It will ask you _How many targets?_ Maybe try 10 at first. It will log what it's doing to standard output and to a log file in the directory it runs in. The log ends with a results summary that should be reasonably clear.

The tricky bit is how the program decides that a packet loss has occurred. It tests each probe by attempting TCP connections, twice for IPv6 and twice for IPv4. It decides there was a packet loss if either

a) one connect() succeeds and the other one fails (both with a timeout of 5 seconds).

or

b) both connects succeed, but one of them takes at least twice as long as the other _and_ exceeds 1 second (which is the default initial RTO in modern TCP stacks).

To avoid unfair resource usage, _probe46_ goes fairly slowly, inserting 1 second of sleep after each connection attempt, and 5 seconds before trying the next probe. So if you try a very large number of probes, it can take several hours. The program saves the log file after every 100 probes, so if there's a crash, you should still get results.

You run this program at your own risk. Read the licence.
