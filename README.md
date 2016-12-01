# montecarlopwd

Monte Carlo password checking, as described in the
[http://www.eurecom.fr/~filippon/Publications/ccs15.pdf]
(ACM CCS 2015 paper) by Matteo Dell'Amico and Maurizio Filippone.

## Write me to get more info!

Very limited documentation right now -- sorry!  If you want to use
this write me (matteo_dellamico@symantec.com) and I'll add docs to
help you do what you need. There's plenty of stuff to help scalability
and persist models; my plan is to write documentation if somebody is
interested in this.

## Dependencies

Python 3 and Numpy (for Python 3, of course!)

## How to Use

Well, if you just want something simple then create a training text
with passwords (repeat passwords that happen more than once!), and
just run example.py. The first argument is the password file; the
program will get passwords to evaluate from standard input (one per
line), and will output the strength estimation (in terms of guesses
needed) with different attack models in a CSV format.

For example, using John the Ripper's password.lst file as training
set, here's a test of "mypassword42"'s strength:

```
$ echo mypassword42 | ./example.py /usr/share/john/password.lst  
password,2-gram,3-gram,4-gram,5-gram,Backoff,PCFG
mypassword42,7.24304921617e+15,4.47184963775e+49,1.11128546873e+13,2806031917.0,7.95632951796e+13,4.09424936607e+36
'''

For anything more complex, just ask and I'll update the documentation!