#!/bin/sh

hadoop fs -mkdir $1/UPDATES
hadoop fs -mv "$1/updates.*.gz" $1/UPDATES/

date '+%F %r' >>messagecount.log
time hadoop jar ./bgpdoop.jar bgpdoop.runner.Runner -Dmapred.child.java.opts="-Xmx1024M" -r$1 -j$2 -n$3 -t$4
date '+%F %r' >>messagecount.log
