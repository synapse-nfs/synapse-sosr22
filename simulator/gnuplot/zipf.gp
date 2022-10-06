set terminal pdf size 5, 5 enhanced color font 'Helvetica,30' linewidth 2
set output 'zipf.pdf'

set key horiz
set key reverse outside top center Left enhanced spacing 1

unset xtics
unset xlabel

set bmargin 3

set ylabel "% traffic sent to controller"

set logscale y
set yrange [ 0.00001 : 100 ] noreverse writeback
set ytics (	\
	"10^{%T}" 0.00001, "" 0.00002 1, "" 0.00003 1, "" 0.00004 1, "" 0.00005 1, "" 0.00006 1, "" 0.00007 1, "" 0.00008 1, "" 0.00009 1, \
	"10^{%T}" 0.0001, "" 0.0002 1, "" 0.0003 1, "" 0.0004 1, "" 0.0005 1, "" 0.0006 1, "" 0.0007 1, "" 0.0008 1, "" 0.0009 1, \
	"10^{%T}" 0.001, "" 0.002 1, "" 0.003 1, "" 0.004 1, "" 0.005 1, "" 0.006 1, "" 0.007 1, "" 0.008 1, "" 0.009 1, \
	"10^{%T}" 0.01, "" 0.02 1, "" 0.03 1, "" 0.04 1, "" 0.05 1, "" 0.06 1, "" 0.07 1, "" 0.08 1, "" 0.09 1, \
	"10^{%T}" 0.1, "" 0.2 1, "" 0.3 1, "" 0.4 1, "" 0.5 1, "" 0.6 1, "" 0.7 1, "" 0.8 1, "" 0.9 1, \
	"1" 1, "" 2 1, "" 3 1, "" 4 1, "" 5 1, "" 6 1, "" 7 1, "" 8 1, "" 9 1, \
	"10" 10, "" 20 1, "" 30 1, "" 40 1, "" 50 1, "" 60 1, "" 70 1, "" 80 1, "" 90 1, \
	"100" 100, "" 200 1, "" 300 1, "" 400 1, "" 500 1, "" 600 1, "" 700 1, "" 800 1, "" 900 1, \
)

set style data histogram
set style histogram clustered gap 0.5 title textcolor lt -1

set style fill solid border 0

set boxwidth 1

set grid ytics lt 0 lw 1 lc rgb "#bbbbbb"
set grid xtics lt 0 lw 1 lc rgb "#bbbbbb"

set linetype 1 linecolor rgb "#88CCEE"
set linetype 2 linecolor rgb "#44AA99"
set linetype 3 linecolor rgb "#117733"
set linetype 4 linecolor rgb "#332288"
set linetype 5 linecolor rgb "#DDCC77"
set linetype 6 linecolor rgb "#999933"
set linetype 7 linecolor rgb "#CC6677"
set linetype 8 linecolor rgb "#882255"
set linetype 9 linecolor rgb "#AA4499"
set linetype 10 linecolor rgb "#DDDDDD"

plot "./data/zipf-min-resources.tsv" using 2 lt 7 t "Min resources", \
	 "./data/zipf-min-cpu-load.tsv" using 2 lt 4 t "Min CPU load", \
	 "./data/zipf-max-throughput.tsv" using 2 lt 1 t "Max throughput"