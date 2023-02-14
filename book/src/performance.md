# Performance
To give you a sense of performance, we benchmarked the action circuit and a vp circuit. 
Action circuit is always the same and has a size about about $2^{15}$ gates, while the VP circuit size changes as the VPs differ from application to application. 
In our benchmarks we used a VP circuit containing about $2^{17}$ gates.

We benchmarked the performance of both circuits on Apple Macbook Air M1 with 16GB RAM.

|Step|Action circuit|VP circuit|Xuyang Action circuit| Xuyang VP circuit|
|-|-|-|-|-|-|
|Prove|1.7s|0.9s|3.3s|1.7s|
|Verify|16.6ms|15ms|32.2ms|33.8ms|