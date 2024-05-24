# Spec-o-Scope
A repo with the code artifacts for the [Spec-o-Scope paper](https://eprint.iacr.org/2024/775)

# Paper Experiments

## Adapting to a different processor
The code in this repository was tested on a Intel Core i5-8250U.
For experimentation on a different processor, the following have to be modified:
* The cache details in `consts.h`.
* The RDTSC threshold between cached/uncached addresses in `consts.h`.
* The Prime+Scope prime pattern in `primescope.h`.
* The gate implementation in `classic_bt_gates.cc`. In particular, delays chains have to be adjusted.
* The LLC slice hash function used for assisted eviction set construction. (`physical_to_slice()` in `util.cc`). 

## Building and Running
```sh
./build.sh
```

To set up a consistent frequency and enable huge pages (for easier eviction set generation) run
```sh
./setup.sh
```

The python scripts require `numpy`, `matplotlib`, `seaborn`, `tqdm`.
```sh
python3 -m pip install -U numpy matplotlib seaborn tqdm
```

## RDTSCP Latency
Run using
```sh
./build/main paper_experiments rdtscp_latency
```
Example output in `paper_expr/rdtscp_latency.res`.

## Gate Types
Run using
```sh
./build/main paper_experiments gate_type > paper_expr/gate_type.txt
```
Process data using
```sh
python3 scripts/paper_gate_type.py
```
Resulting graph is in `paper_expr/gate_type.png`.

## Multiple Measurement Rate
Run using
```sh
./build/main paper_experiments multi_sample_rates > paper_expr/multi_sample_rates.txt
```
Process data using
```sh
python3 scripts/paper_multi_sample_rates.py
```
Resulting graphs are in `paper_expr/multi_sample_rates_y{0,40}.png`.

## Minimum Distinguishable Difference
Run using
```sh
sudo ./build/md_main test_aes_break min_distinguish > paper_expr/min_distinguish.txt
```
Note, the use of `sudo` is for construction of eviction sets.

Process data using
```sh
python3 scripts/paper_min_distinguish.py
```
Resulting graph is in `paper_expr/min_distinguish_a2.png`.

## AES TTable First Round Attack
Run attack using
```sh
sudo ./build/main test_aes_break ttable_msb -o paper_expr/ttable_msb.txt
```

### First Round Oracle
Generate graph using
```sh
python3 scripts/paper_ttable_msb_oracle.py
```
Resulting graph is in `paper_expr/ttale_msb_oracle.png`.

### First Round Traces
Process data using
```sh
python3 scripts/aes_ttable_correlation_score_mp.py
```

Generate graph using
```sh
python3 scripts/paper_ttable_msb_traces.py
```
Resulting graph is in `paper_expr/ttable_msb_traces.png`.
Example output is in `paper_expr/ttable_msb_traces.res`.

## AES TTable Second Round Attack
Run attack using
```sh
sudo ./build/main test_aes_break ttable_sr -o paper_expr/ttable_sr.txt
```

Process data using
```sh
./build/ttable_sr_analysis
```

Generate graph using
```sh
python3 scripts/paper_ttable_sr_traces.py
```
Resulting graph is in `paper_expr/ttable_sr_traces.png`.
Example output is in `paper_expr/ttable_sr_traces.res`.

## AES SBox First Round Attack
Run attack using
```sh
sudo ./build/main test_aes_break sbox_msb -o paper_expr/sbox_msb.txt
```

### First Round Threshold
Process data using
```sh
python3 scripts/paper_witness_threshold.py
```
Resulting graph is in `paper_expr/sbox_msb_threshold.png`.

### First Round Oracle
Process data using
```sh
python3 scripts/paper_sbox_msb_oracle.py
```
Resulting graph is in `paper_expr/sbox_msb_oracle.png`.

### First Round Traces
Process data using
```sh
python3 scripts/aes_sbox_2msb_new.py
```

Generate graph using
```sh
python3 scripts/paper_sbox_msb_traces.py
```
Resulting graph is in `paper_expr/sbox_msb_traces.png`.
Example output is in `paper_expr/sbox_msb_traces.res`.

## AES SBox Second Round Attack
Run attack using
```sh
sudo ./build/main test_aes_break2 sbox_sr_adaptive -o paper_expr/sbox_sr.txt 2> paper_expr/sbox_sr_traces.txt
```

### Second Round Oracle
Process data using
```sh
python3 scripts/paper_sbox_sr_oracle.py
```
Resulting graph is in `paper_expr/sbox_sr_oracle.png`.

### Second Round Pearson Correlation
Process data using
```sh
python3 scripts/paper_sbox_sr_pearson.py
```
Resulting graph is in `paper_expr/sbox_sr_pearson.png`.

### Second Round Trace Count
Process data using
```sh
python3 scripts/paper_sbox_sr_traces.py
```
Resulting graph is in `ppaper_expr/sbox_sr_traces.png`.

### Second Round Attack Results
Process data using
```sh
./build/sbox_sr_analysis
```
Example output is in `paper_expr/sbox_sr_attack.res`.

## Second Round Pearson Cumulative
Process data using
```sh
./build/sbox_sr_analysis
```

Generate graph using
```sh
python3 scripts/paper_pearson_cumulative.py
```
Resulting graph is in `paper_expr/pearson_cumulative.png`.
