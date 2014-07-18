#!/bin/sh
F=$1

cat $F |fgrep -v total|perl -pi -e 's/(.*),.* in=(.+) out=(.+) filtered=(.+)/$1,$2,$3,$4/' > tmpplot.csv

gnuplot <<END
set terminal png size 1024,768
set output "dumbno.png"
set ylabel "mbps"
set datafile separator ","

set xdata time
set timefmt "%s"
set timefmt "%Y-%m-%d %H:%M:%S"
set format x "%Y-%m-%d"

set ylabel "mbps"
plot "tmpplot.csv" using 1:2 with lines title "in" ,\
     "tmpplot.csv" using 1:3 with lines title "out" ,\

END
