# SBOMInsight

SBOMInsight - Gain deep insights and secure your software supply chain 


## Usage 

To generate an SBOM from an image and output it in JSON format:

> sbominsight -i alpine:latest      

To generate an SBOM from an image and output it in table format:

> sbominsight -i alpine:latest -o table 

+------------------+------------------------+-------------+------+
|        ID        |          NAME          |   VERSION   | TYPE |
+------------------+------------------------+-------------+------+
| 21e54be9d7ca763c | alpine-baselayout      | 3.6.5-r0    | apk  |
| 9ff96f942d2401f2 | alpine-baselayout-data | 3.6.5-r0    | apk  |
| 0e5100e3d266a135 | alpine-keys            | 2.4-r1      | apk  |
| 78c55d64ab350462 | apk-tools              | 2.14.4-r0   | apk  |
| 1bb81cc0e13f362d | busybox                | 1.36.1-r29  | apk  |
| 30b5e2f594950cb2 | busybox-binsh          | 1.36.1-r29  | apk  |
| bf42440dd0b61727 | ca-certificates-bundle | 20240226-r0 | apk  |
| 08245537a7b7e2c2 | libcrypto3             | 3.3.1-r0    | apk  |
| 32dba27fbdfd12ba | libssl3                | 3.3.1-r0    | apk  |
| 03e521237cbed45a | musl                   | 1.2.5-r0    | apk  |
| c84ae08b59df5c6e | musl-utils             | 1.2.5-r0    | apk  |
| 54f3623fdd8fb8d4 | scanelf                | 1.3.7-r2    | apk  |
| 692d7c5cf4a3b25a | ssl_client             | 1.36.1-r29  | apk  |
| d8258d3d7c48cfbf | zlib                   | 1.3.1-r1    | apk  |
+------------------+------------------------+-------------+------+


## Installation

To install SBOMInsight, use the following commands:

```
git clone github.com/sangam14/sbominsight
go build -o sbominsight
```

## Contributing

We welcome contributions from the community! ♻️ 