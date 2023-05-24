# Performance
To give you a sense of performance, we benchmarked the action circuit and a simple VP circuit. 
Action circuit is always the same and has a size about about $2^{13}$ gates, while the VP circuit size changes as the VPs differ from application to application. 
In our benchmarks we used a VP circuit containing about $2^{13}$ gates.

|Step|Action circuit|VP circuit|
|-|-|-|
|Prove|3.3s|1.7s|
|Verify|32.2ms|33.8ms|

We benchmarked the performance of both circuits on Apple Macbook Air M1 with 16GB RAM.
