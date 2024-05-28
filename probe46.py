#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check and time IPv6 vs IPv4 ATLAS probes chosen at random"""

########################################################
# Released under the BSD "Revised" License as follows:
#                                                     
# Copyright (C) 2024 Brian E. Carpenter.                  
# All rights reserved.
#
# Redistribution and use in source and binary forms, with
# or without modification, are permitted provided that the
# following conditions are met:
#
# 1. Redistributions of source code must retain the above
# copyright notice, this list of conditions and the following
# disclaimer.
#
# 2. Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following
# disclaimer in the documentation and/or other materials
# provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of
# its contributors may be used to endorse or promote products
# derived from this software without specific prior written
# permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS  
# AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED 
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A     
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)    
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING   
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE        
# POSSIBILITY OF SUCH DAMAGE.                         
#                                                     
########################################################

# 20240528 first release

import time
import socket
import ipaddress
import random

# import Atlas probe API
try:
    from ripe.atlas.cousteau import Probe
except:
    print("Could not import Probe",
        "\nPlease install ripe.atlas.cousteau with pip or apt-get.")
    input("Press 'Enter' to exit.")
    exit()

def log(*whatever):
    """Log and print"""
    s=""
    for x in whatever:          
        try:               
            s += str(x)+" "
            print(x,end=" ",flush=False)
        except:
            #in case UTF-8 string (or something else) can't be printed
            print("[unprintable]",end="",flush=False)
    print("")
    log_file.write(s+"\n")

def ratio(a, b):
    """Ratio of larger to smaller"""
    if a and b:
        return(max(a,b)/min(a,b))
    else:
        return(1)



def ok(da, repeat = False):
    """Check a target. Return False if bad, latency in ms if OK"""

    #Does one retry if timeout occurs

    global timed_out4, timed_out6, ok4, ok6
    global low4, high4, low6, high6, lat_total4, lat_total6, err_not_to

    try:
        if da.version == 6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            t0 = time.monotonic()
            sock.connect((str(da), 80, 0, 0))
            latency = max(int((time.monotonic() - t0)*1000),1) #1 ms minimum
            ok6 += 1
            lat_total6 += latency
            if latency > high6:
                high6 = latency
            if latency < low6:
                low6 = latency
        else:        
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            t0 = time.monotonic()
            sock.connect((str(da), 80))
            latency = max(int((time.monotonic() - t0)*1000),1) #1 ms minimum
            ok4 +=1
            lat_total4 += latency
            if latency > high4:
                high4 = latency
            if latency < low4:
                low4 = latency
        sock.close()
    except Exception as ex:
        try:
            sock.close() #ensure socket not left open
        except:
            pass
        latency = False
        log("!connect", ex, da)
        if "timed out" in str(ex):
            if da.version == 6:
                timed_out6 += 1
            else:
                timed_out4 += 1
        else:
            err_not_to += 1
    latency2 = False
    if not repeat:
        time.sleep(1)
        latency2, _ = ok(da, repeat = True) #recurse, but only once             
    return(latency, latency2)

def do4():
    """heuristic for v4"""
    global target4, loss4, fail4
    r4a, r4b = ok(target4)
    time.sleep(1)    #avoid looking like a DoS
    if r4a and r4b:
        #double success
        log("v4:", r4a, r4b)
        if ratio(r4a, r4b) >= 2 and max(r4a, r4b) > 1000:
            #consider one of those was a retry
            log("!retry4?", r4a, r4b)
            loss4 += 1
    elif (not r4a) and (not r4b):
        #double failure
        fail4 += 1
        return(False)
    else:
        #single failure, call it a loss
        log("!loss4?", r4a, r4b)
        loss4 += 1
    return(True)
    

def do6():
    """heuristic for v6"""
    global target6, loss6, fail6
    r6a, r6b = ok(target6)
    time.sleep(1)    #avoid looking like a DoS
    if r6a and r6b:
        #double success
        log("v6:", r6a, r6b)
        if ratio(r6a, r6b) >= 2 and max(r6a, r6b) > 1000:
            #consider one of those was a retry
            log("!retry6?", r6a, r6b)
            loss6 += 1
    elif (not r6a) and (not r6b):
        #double failure
        fail6 += 1
        return(False)
    else:
        #single failure, call it a loss
        log("!loss6?", r6a, r6b)
        loss6 += 1
    return(True)

def log_results():
    """Send results to log and standard output"""
    log()
    log(poll_count, "targets tested.")
    if ok6:
        log(ok6, "successful IPv6 probes; mean latency", round(lat_total6/ok6), "ms.")
    log("Max =", high6, "; min =", low6, "ms.")
    if ok4:
        log(ok4, "successful IPv4 probes; mean latency", round(lat_total4/ok4), "ms.")
    log("Max =", high4, "; min =", low4, "ms.")
    log(only6, "probe(s) succeeded only for IPv6.")
    log(timed_out6, "IPv6 timeout(s)observed ;", fail6, "IPv6 target(s) failed completely.")
    log(loss6, "IPv6 packet loss(es) inferred out of", 2*poll_count)
    log(only4, "probe(s) succeeded only for IPv4.")
    log(timed_out4, "IPv4 timeout(s) observed;", fail4, "IPv4 target(s) failed completely.")
    log(loss4, "IPv4 packet loss(es) inferred out of", 2*poll_count)
    log(doubles, "target(s) failed for both IPv4 and IPv6.")
    log(err_not_to, "non-timeout error(s).")
    

#############################################
# Initialisations                           #
#############################################

prng = random.SystemRandom()
tryp = None         #current probe ID
poll_count = 0      #count targets that have been polled
timed_out4 = 0      #count v4 timeouts
timed_out6 = 0      #count v6 timeouts
fail4 = 0           #count v4 fails
fail6 = 0           #count v6 fails
ok4 = 0             #count successful v4 probes
ok6 = 0             #count successful v6 probes
only4 = 0           #count v4-only successes
only6 = 0           #count v6-only successes
doubles = 0         #count double failures
lat_total4 = 0      #v4 latency total (ms)
lat_total6 = 0      #v6 latency total
low4 = 1000000      #v4 lowest latency
low6 = 1000000      #v6 lowest latency
high4 = 0           #v4 highest latency
high6 = 0           #v6 highest latency
loss4 = 0           #v4 loss count
loss6 = 0           #v6 loss count

err_not_to = 0      #count non-timeout socket errors

timeout = 5         #connect timeout (seconds)
maxct = 0           #maximum target count

print("IPv6/IPv4 probe test program")
while not maxct:
    try:
        maxct = int(input("How many targets? "))
        if maxct < 2 or maxct > 1000:
            print("Out of range!")
            maxct = 0
    except:
        print("Invalid!")

timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC%z",time.localtime())
filename = timestamp.replace(" ","_").replace(":","")+".log"
log_file = open(filename, "a")

log("IPv6 probing run at", timestamp)
log("Will probe", maxct, "randomly chosen dual stack Atlas probe targets.\n")

while poll_count < maxct:

    if poll_count and not poll_count%100:
        # log results so far and save file
        log_results()
        log_file.close()
        log_file = open(filename, "a")
    
    #select a random global probe target
    #we try 10 times, if that fails we're in trouble
    target6 = None
    target4 = None
    for i in range(1,10):
        tryp = prng.randint(6000, 7200)
        try:
            probe = Probe(id=tryp)
            if probe.is_anchor and probe.status == 'Connected' and probe.address_v6 and probe.address_v4:
                target6 = ipaddress.IPv6Address(probe.address_v6)
                target4 = ipaddress.IPv4Address(probe.address_v4)
                if target6.isglobal() and target4.isglobal():
                    if probe.system_ipv4_stable_1d and probe.system_ipv6_stable_1d:
                        break
        except:
            pass

       
    log(poll_count, ": Chose", target6, "and", target4, "(Probe #", tryp, ")")

    poll_count += 1

    #alternate order of polling
    if poll_count%2:
        r4 = do4()
        r6 = do6()
    else:
        r6 = do6()
        r4 = do4()

    if r4 and not r6:
        only4 += 1
    if r6 and not r4:
        only6 += 1
    if (not r6) and (not r4):
        doubles +=1
    time.sleep(5) #avoid looking like a DoS

log_results()
log_file.close()
input("Press 'Enter' to exit.")

        
        
 

   


                




    
