set terminal pdf size 5, 5 enhanced color font 'Helvetica,30' linewidth 2
set output 'churn-cpu-load.pdf'

set key horiz
set key reverse outside top center Left enhanced spacing 1

set xlabel "Churn (fpm)"

set xtics border in scale 0,0 nomirror autojustify
set xtics norangelimit 
set xtics ()
		
set ylabel "Relative CPU load"

set ytics 4
set yrange [ 0 : * ] noreverse writeback

set style data histogram
set style histogram clustered gap 2 title textcolor lt -1

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

plot "./data/churn-min-resources.tsv" using 3:xtic(1) lt 7 t "Min resources", \
	 "./data/churn-min-cpu-load.tsv" using 3:xtic(1) lt 4 t "Min CPU load", \
	 "./data/churn-max-throughput.tsv" using 3:xtic(1) lt 1 t "Max throughput"
