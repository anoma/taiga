# NUM_NOTE = 4

```
Compile:
VP(2^17)-compile_with_blinding          secs: 17, nanos: 505948000
Action(2^15)                            secs: 4, nanos: 975182000
Blind VP(2^15)                          secs: 17, nanos: 505948000

Prove:
VP(2^17)                                secs: 17, nanos: 735556000
Action(2^15)                            secs: 4, nanos: 678785000
Blind VP(2^15)                          secs: 19, nanos: 338197000

Verify
VP(2^17)                                secs: 0, nanos: 14212000
Action(2^15)                            secs: 0, nanos: 9618000
Blind VP(2^15)                          secs: 0, nanos: 43840000
```

```
tx(4 actions, 16 vps, 16 vp blinds)
tx prove+vp compile:                    secs: 1160, nanos: 198469000
verify:                                 secs: 0, nanos: 844403000
```

# NUM_NOTE = 3

```
Compile:
VP(2^16)-compile_with_blinding          secs: 10, nanos: 87050000

Prove:
VP(2^16)                                secs: 10, nanos: 71476000
```

```
tx(2 actions, 8 vps, 8 vp blinds)
tx prove+vp compile:                    secs: 591, nanos: 227595000
verify:                                 secs: 0, nanos: 587065000
```

# NUM_NOTE = 2

```
Compile:
VP(2^16)-compile_with_blinding          secs: 9, nanos: 987286000

Prove:
VP(2^16)                                secs: 9, nanos: 946505000
```

```
tx(2 actions, 8 vps, 8 vp blinds)
tx prove+vp compile:                    secs: 436, nanos: 500172000
verify:                                 secs: 0, nanos: 555699000
```