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