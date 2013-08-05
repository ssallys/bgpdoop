#!/bin/sh

list=`cat routeview.lists`
job=c
reduces=30
table=msgcount

for src in $list
do

	hadoop fs -mkdir $src/UPDATES
	hadoop fs -mv "$src/updates.*.gz" $src/UPDATES/

	time hadoop jar ./bgpdoop.jar bgpdoop.runner.Runner -Dmapred.child.java.opts="-Xmx1024M" -r$src -j$job -n$reduces -t$table

done
