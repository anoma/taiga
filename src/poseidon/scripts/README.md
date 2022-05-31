# Poseidon Parameters Generation

## Round number calculation script
Command usage:
```shell
Usage: <script> <N> <t> <M> <field_case> <sbox_case>
<N>: N = t * bits_num
<t>:
<M>: security bits
<field_case>: 0 for binary, 1 for prime
<sbox_case>: 0 for x^3, 1 for x^5, 2 for x^(-1)
```
## Parameters generation script
Command usage:
```shell
Usage: <script> <field> <s_box> <field_size> <num_cells> <R_F> <R_P> <prime_number_hex>

<script>: generate_parameters_grain_deterministic.sage
<field>: 0 for GF(2^n), 1 for GF(p)
<s_box>: 0 for x^alpha; 1 for x^(-1)
<field_size>:
<num_cells>: width
<R_F>: num of full round
<R_P>: num of partial round
<prime_number_hex>: hex format of prime
```

## Hash computation script
* Input the hash parameters in script
* Generate the hash result of Fr(1) and Fr(2) with width 3 by default.

# BLS12-377
## Round number calculation for BLS12-377 scalar field
```shell
python3 calc_round_numbers.py 759 3 128 1 1
```

## Parameters generation for BLS12-377 scalar field
```shell
sage generate_parameters_grain_deterministic.sage 1 0 253 3 8 55 0x12ab655e9a2ca55660b44d1e5c37b00159aa76fed00000010a11800000000001
```

## Hash computation
```shell
sage poseidonperm_bls12_377_width3.sage
```