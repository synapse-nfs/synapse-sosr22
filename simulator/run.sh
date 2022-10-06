#!/bin/bash

set -eou pipefail

# Jump into the script directory
SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
cd $SCRIPT_DIR

DAT_DIR=./data
PCAPS_DIR=./pcaps
PLOTS_DIR=./plots
SIMULATORS_DIR=./simulators
GNUPLOT_DIR=./gnuplot
TMP=.tmp

IMC_10_TRACE=univ2_trace.tgz
IMC_10_TRACE_URL=https://pages.cs.wisc.edu/~tbenson/IMC_DATA/$IMC_10_TRACE
IMC_10_TRACE_CHOSEN=univ2_pt1

CHURN_SCRIPT=churn
CHURN_PCAPS=(
    churn_1000000_fpm.pcap
    churn_10000000_fpm.pcap
    churn_100000000_fpm.pcap
)

UNIV_PCAP=univ2_pt1.pcap

cleanup() {
    pushd $PCAPS_DIR > /dev/null
        rm -f .partition*
        find . -type f -name "univ2_pt*" ! -name "$UNIV_PCAP" -delete
        rm -f *.dat
    popd > /dev/null
}
trap cleanup EXIT

get_univ_trace() {
    pushd $PCAPS_DIR > /dev/null
        if [ ! -f $UNIV_PCAP ]; then
            echo "[*] University trace missing."

            if [ ! -f $IMC_10_TRACE ]; then
                echo "[*] Benson's traces not found. Pulling..."
                wget $IMC_10_TRACE_URL
            else
                echo "[*] Benson's traces found!"
            fi

            echo "[*] Extracting traces..."
            tar xzf $IMC_10_TRACE

            mv $IMC_10_TRACE_CHOSEN $TMP
            rm -f univ2_pt*
            mv $TMP $UNIV_PCAP
        else
            echo "[*] University trace found!"
        fi
    popd > /dev/null
}

build_churn_pcaps() {
    pushd $PCAPS_DIR > /dev/null
        built=false

        for pcap in ${CHURN_PCAPS[@]}; do
            churn=$(echo $pcap | grep -oP "\d+")

            if [ ! -f $pcap ]; then
                if [ "$built" == false ]; then
                    echo "[*] Building churn script"
                    make
                    built=true
                fi

                echo "[*] $churn fpm churn trace not found. Creating..."
                ./build/$CHURN_SCRIPT $UNIV_PCAP $pcap $churn
            else
                echo "[*] $churn fpm churn trace found!"
            fi

        done
    popd > /dev/null
}

get_pcaps() {
    get_univ_trace
    build_churn_pcaps
}

build_simulators() {
    echo "[*] Building simulators"
    pushd $SIMULATORS_DIR > /dev/null
        make -j
    popd > /dev/null
}

run_churn_simulation() {
    echo "[*] Running churn simulation"

    for pcap in ${CHURN_PCAPS[@]}; do
        churn=$(echo $pcap | grep -oP "\d+")
        churn_hr=$(python3 -c "print('{:,}'.format($churn))")
        mkdir -p $DAT_DIR

        pcap_path=$PCAPS_DIR/$pcap

        solution=min-resources
        exec=$SIMULATORS_DIR/build/$solution
        out=$DAT_DIR/churn-$churn-fpm-$solution.dat

        echo "  $solution ($churn_hr fpm)"
        $exec $pcap_path > $out

        solution=min-cpu-load
        exec=$SIMULATORS_DIR/build/$solution
        out=$DAT_DIR/churn-$churn-fpm-$solution.dat
        
        echo "  $solution ($churn_hr fpm)"
        $exec $pcap_path > $out

        solution=max-throughput
        exec=$SIMULATORS_DIR/build/$solution
        out=$DAT_DIR/churn-$churn-fpm-$solution.dat
        
        echo "  $solution ($churn_hr fpm)"
        $exec $pcap_path > $out
    done
}

run_zipf_simulation() {
    echo "[*] Running zipf simulation"
    mkdir -p $DAT_DIR

    solution=min-resources
    exec=$SIMULATORS_DIR/build/$solution
    out=$DAT_DIR/zipf-$solution.dat
    
    echo "  $solution"
    $exec $PCAPS_DIR/$UNIV_PCAP > $out

    solution=max-throughput
    exec=$SIMULATORS_DIR/build/$solution
    out=$DAT_DIR/zipf-$solution.dat

    echo "  $solution"
    $exec $PCAPS_DIR/$UNIV_PCAP > $out

    cp $DAT_DIR/zipf-max-throughput.dat $DAT_DIR/zipf-min-cpu-load.dat
}

generate_plots() {
    echo "[*] Process zipf simulation data files"
    $DAT_DIR/data-handler-zipf.py

    echo "[*] Process churn simulation data files"
    $DAT_DIR/data-handler-churn.py

    echo "[*] Generate plots"
    gnuplot $GNUPLOT_DIR/zipf.gp
    gnuplot $GNUPLOT_DIR/zipf-cpu-load.gp

    gnuplot $GNUPLOT_DIR/churn.gp
    gnuplot $GNUPLOT_DIR/churn-cpu-load.gp

}

get_pcaps
build_simulators

run_zipf_simulation
run_churn_simulation

generate_plots