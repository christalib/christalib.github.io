---
layout: post
title: "Fake Wire app infected by Finspy"
date: 2021-06-12
---

_I'd like to thanks Defensive Lab Agency and especially Esther for her help in the work on this sample_

A couple of weeks ago, a suspicious sample that was masquerading the chat application Wire was detected. To our surprise, the application was detected as a Finspy sample based on [rules written](https://defensive-lab.agency/2020/09/finspy-android/#sample-behavioral-analysis) in 2020 by Defensive Lab Agency and Amnesty.

It is interesting to note that it seems to be the first time to have a Finspy sample is targetting a popular application. Wire didn't seem to comment on that issue after being contacted through Twitter.

## Overview

| Field   | Value                                                            |
| ------- | ---------------------------------------------------------------- |
| Size    | 40.68MB                                                          |
| MD5     | e162504122c224d4609ade9efa9af82d                                 |
| SHA-1   | 4718bcf28bfffac1922a5c9f25140165563d6164                         |
| SHA-256 | ae05bbd31820c566543addbb0ddc7b19b05be3c098d0f7aa658ab83d6f6cd5c8 |
| Package | org.xmlpush.v3.StartVersion                                      |

Certificate:

| Field                        | Value                                                                                                                                |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| MD5                          | 6c6dd54955725ae5414c20e0a67ef6e4                                                                                                     |
| SHA1                         | 341c22ce9ab4e1008d3d507e5e8b3451a4efc2be                                                                                             |
| SHA256                       | e14f254656ff869bb738aec58656042171c8625c9defbcc6eb4f24d41d4ec929                                                                     |
| Issuer                       | Common Name: Unknown, Organizational Unit: Unknown, Organization: Zeta, Locality: Unknown, State/Province: Unknown, Country: Unknown |
| Owner                        | C=Unknown, ST=Unknown, L=Unknown, O=Zeta, OU=Unknown, CN=Unknown                                                                     |
| Signature Algorithm          | SHA256withRSA                                                                                                                        |
| Subject Public Key Algorithm | 2048-bit RSA key                                                                                                                     |
| Version                      | 3                                                                                                                                    |
| Not Before                   | 2021-04-26T10:51:28+00:00                                                                                                            |
| Not After                    | 2048-09-10T10:51:28+00:00                                                                                                            |

## What Wire version is affected?

The analysed sample mimics the version 3.65.979 (2021/03/01).

## Timeline?

- First upload on VT (2021-05-19 04:31:51 UTC) [Link](https://www.virustotal.com/gui/file/ae05bbd31820c566543addbb0ddc7b19b05be3c098d0f7aa658ab83d6f6cd5c8/detection)
- First upload on Pithus (2021-04-27T17:20:58.926579) [Analyse](https://beta.pithus.org/report/ae05bbd31820c566543addbb0ddc7b19b05be3c098d0f7aa658ab83d6f6cd5c8)
- [Twitter](https://twitter.com/U039b/status/1387487404160860166)

## What is the configuration of this malware?

We detected the application using the Yara rules developped by Defensive Lab Agency for their work on the [Finspy samples in 2020](https://defensive-lab.agency/2020/09/finspy-android/). We can safely assume that those samples embbed the same artifacts and the same type of behaviour.

We extracted the configuration with the [tools provided](https://github.com/DefensiveLabAgency/FinSpy-for-Android) by Defensive Lab Agency and Amnesty:

- C2: 78.46.120[.]20:443 (Hetzner) [VT](https://www.virustotal.com/gui/ip-address/78.46.120.20/relations)
- C2: qa-demo.wire[.]link (Gandi) [VT](https://www.virustotal.com/gui/domain/qa-demo.wire.link/relations). Registered on 2018-09-05, expires on 2021-09-05. The [whois data](https://www.whois.com/whois/wire.link) seems different form the [legit](https://www.whois.com/whois/wire.com) `wire[.]com` website.

[Here](https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/fin7.txt) is a list of all the Finspy network indicators. It was updated with the detection discussed in this article.

| TLV value | TLV Name                                 | Associated Value                                                                                                                                                                                                                                                                               |
| --------- | ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 16651088  | TlvTypeRequestID                         | 0                                                                                                                                                                                                                                                                                              |
| 16668512  | TlvTypeMobileTargetUID                   | `00 00 00 00 00 00 00 00`                                                                                                                                                                                                                                                                      |
| 16651584  | TlvTypeVersion                           | 0                                                                                                                                                                                                                                                                                              |
| 16668784  | TlvTypeMobileTargetID                    | 600                                                                                                                                                                                                                                                                                            |
| 8675648   | TlvTypeMobileTargetHeartbeatInterval     | 300                                                                                                                                                                                                                                                                                            |
| 8689712   | Unknown                                  | `00`                                                                                                                                                                                                                                                                                           |
| 8676496   | TlvTypeMobileTargetPositioning           | `82 87 86 81 83`                                                                                                                                                                                                                                                                               |
| 8678192   | Unknown                                  | `01`                                                                                                                                                                                                                                                                                           |
| 8678448   | Unknown                                  | `01`                                                                                                                                                                                                                                                                                           |
| 8402800   | TlvTypeConfigTargetProxy                 | 78.46.120[.]20                                                                                                                                                                                                                                                                                 |
| 8403008   | TlvTypeConfigTargetPort                  | 443                                                                                                                                                                                                                                                                                            |
| 8676208   | TlvTypeConfigSMSPhoneNumber              | +780702441553                                                                                                                                                                                                                                                                                  |
| 8676976   | TlvTypeMobileTrojanID                    | 600                                                                                                                                                                                                                                                                                            |
| 8676672   | TlvTypeMobileTrojanUID                   | 8819601                                                                                                                                                                                                                                                                                        |
| 16654656  | TlvTypeUserID                            | 1000                                                                                                                                                                                                                                                                                           |
| 8392000   | TlvTypeTrojanMaxInfections               | 5                                                                                                                                                                                                                                                                                              |
| 8677440   | TlvTypeConfigMobileAutoRemovalDateTime   | 0                                                                                                                                                                                                                                                                                              |
| 8403776   | TlvTypeConfigAutoRemovalIfNoProxy        | 168                                                                                                                                                                                                                                                                                            |
| 8675472   | TlvTypeMobileTargetHeartbeatEvents       | - SIM changed: True<br>- Cell location changed: False<br>- Network changed: True<br>- Call: False<br>- Wifi connected: True<br>- Data link available: True<br>- Network activated: False<br>- Data available: True<br>                                                                         |
| 8675984   | TlvTypeMobileTargetHeartbeatRestrictions | `d0 00`                                                                                                                                                                                                                                                                                        |
| 8677296   | TlvTypeMobileTargetLocationChangedRange  | `00`                                                                                                                                                                                                                                                                                           |
| 8681872   | TlvTypeInstalledModules                  | - Spy calls: False<br>- Intercept calls: False<br>- SMS: True<br>- Address book: True<br>- Logging: False<br>- Location: True<br>- Call log: True<br>- Calendar: True<br>- Spy chats: True                                                                                                     |
| 4535440   | TlvTypeMobileTrackingConfigRaw           | `56 00 00 00 a0 33 45 00 0c 00 00 00 40 41 45 00 e8 03 00 00 0c 00 00 00 40 40 45 00 2c 01 00 00 0c 00 00 00 40 44 45 00 e8 03 00 00 0c 00 00 00 40 43 45 00 2c 01 00 00 09 00 00 00 30 42 45 00 00 09 00 00 00 30 52 45 00 00 0c 00 00 00 90 64 84 00 85 00 00 00 `                           |
| 5521552   | Unknown                                  | `5c 00 00 00 a0 40 54 00 0c 00 00 00 40 44 fe 00 50 00 00 00 09 00 00 00 30 43 fe 00 01 0c 00 00 00 40 46 fe 00 28 00 00 00 0c 00 00 00 40 45 fe 00 05 00 00 00 09 00 00 00 30 97 fe 00 00 09 00 00 00 30 98 fe 00 01 0c 00 00 00 50 99 fe 00 02 00 00 00 09 00 00 00 30 02 54 00 01`          |
| 5456016   | Unknown                                  | `5f 00 00 00 a0 41 53 00 0c 00 00 00 40 44 fe 00 50 00 00 00 09 00 00 00 30 43 fe 00 01 0c 00 00 00 40 46 fe 00 28 00 00 00 0c 00 00 00 40 45 fe 00 05 00 00 00 09 00 00 00 30 97 fe 00 00 09 00 00 00 30 98 fe 00 01 0c 00 00 00 50 99 fe 00 02 00 00 00 0c 00 00 00 40 3f fe 00 00 00 00 00` |
| 5570960   | Unknown                                  | `14 00 00 00 a0 02 55 00 0c 00 00 00 40 42 fe 00<br>11 2b 00 00`                                                                                                                                                                                                                               |
| 5644432   | Unknown                                  | `3b 00 00 00 a0 21 56 00 09 00 00 00 30 23 56 00 01 09 00 00 00 30 25 56 00 01 09 00 00 00 30 24 56 00 01 0c 00 00 00 40 22 56 00 00 00 00 ff 0c 00 00 00 40 26 56 00 1e 00 00 ff`                                                                                                             |
| 16647056  | TlvTypeEncryption                        | `43 58 50 5d 4f 59 06 43 53 5f 35 4a 52 30 0e 5b 2d 5e 27 4b 40 0f 36`                                                                                                                                                                                                                         |

## String obfuscation (TippyPad)

In the same fashion as the sample previously analysed by Defensive Lab Agency, strings are obfuscated with the same pattern.

- `String o1IoIlolii0lOio1Il1001(int i)` returns the obfuscated string as bytes at the given index.
- `lloilioi1oi01I0I0liO(byte[] bArr, byte[] bArr2)` decodes an obfuscated string

```java
 private static byte[] lloilioi1oi01I0I0liO(byte[] bArr, byte[] bArr2) {
        byte[] bArr3 = new byte[bArr2.length];
        for (int i = 0; i < bArr2.length; i++) {
            bArr3[i] = (byte) (bArr2[i] ^ bArr[i % bArr.length]);
        }
        return bArr3;
    }

    private static String o1IoIlolii0lOio1Il1001(int i) {
        byte[] bArr = {48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102};
        byte[] bArr2 = {102, 101, 100, 99, 98, 97, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48};
        ArrayList arrayList = new ArrayList();
        arrayList.add(new byte[]{81, 95, 86, 65, 91, 92, 82, 104, 81, 93});
        arrayList.add(new byte[]{39, 32, 55});
        arrayList.add(new byte[]{113, 116, 97});
        return new String(lloilioi1oi01I0I0liO(i % 2 == 0 ? bArr : bArr2, (byte[]) arrayList.get(i)));
    }
}
```

The two pads are the same as the previous sample which was detected as TippyPad:

- `0123456789abcdef`
- `fedcba9876543210`

## Local socket address generation (TippyTime)

The local socket address generation is similar to the previous samples:

```java
    public static int m2108c(String str) {
        Ii0I011oo0iiOIlI00();
        byte[] bytes = str.getBytes();
        int length = bytes.length;
        int i = length / 4;
        int i2 = length ^ 0;
        int i3 = 0;
        while (i3 < i) {
            int i4 = i3 * 4;
            int i5 = (((bytes[i4 + 3] & 255) << 24) + (bytes[i4 + 0] & 255) + ((bytes[i4 + 1] & 255) << 8) + ((bytes[i4 + 2] & 255) << 16)) * 1540483477;
            i3++;
            i2 = ((i5 ^ (i5 >>> 24)) * 1540483477) ^ (i2 * 1540483477);
        }
        switch (length % 4) {
            case 3:
                i2 ^= (bytes[(length & -4) + 2] & 255) << 16;
            case 2:
                i2 ^= (bytes[(length & -4) + 1] & 255) << 8;
            case 1:
                i2 = (i2 ^ (bytes[length & -4] & 255)) * 1540483477;
                break;
        }
        int i6 = (i2 ^ (i2 >>> 13)) * 1540483477;
        return i6 ^ (i6 >>> 15);
    }
```

## Suspicious ELFs found in the app

Most of our work was following the steps of Defensive Lab Agency and Amnesty. Further down in the analysis, there was some suspicious strings that looked like binary data. After contacting Defensive Lab Agency, they mentionned having found them as well.

There are a couple of java files that are larger than 2 megabytes:

```bash
-> find . -size +2M
./da2b11bb/b094ffd.java
./da2b11bb/afbffbc.java
```

With some Frida hooks, we managed to get the strings:

```python
import frida

jscode = """
console.log("script loaded");
Java.perform(function () {
    const evilClass = Java.use("org.xmlpush.v3.da2b11bb.d552b92f");
    let stage1 = evilClass.o1IoIlolii0lOio1Il1001(1);

    let bytes = [];
    let stage2 = [];
    for (let i = 0; i < stage1.length; i++) {
        let code = stage1.charCodeAt(i);
        let stage2 = bytes.concat([code]);
    }

    // m2404c(byte[]) -> byte[]
    let stage3 = evilClass.c();
    console.log(stage3)

    let buffer = Java.array("byte", stage3);
    let result = "";
    for (let i = 0; i < buffer.length; ++i){
        result+= (String.fromCharCode(buffer[i]));
    }

    console.log(result);
    });
"""

if __name__ == '__main__':
    process = frida.get_device('emulator-5554').attach('com.wire')
    script = process.create_script(jscode)
    script.load()

```

And analysing the result:

```
-> % readelf -h res.bin [1]
ELF Header:
Magic: 7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
Class: ELF32
Data: 2's complement, little endian
Version: 1 (current)
OS/ABI: UNIX - System V
ABI Version: 0
Type: DYN (Shared object file)
Machine: ARM
Version: 0x1
Entry point address: 0x810
Start of program headers: 52 (bytes into file)
Start of section headers: 463781871 (bytes into file)
Flags: 0x2, GNU EABI, <unknown>
Size of this header: 1280 (bytes)
Size of program headers: 52 (bytes)
Number of program headers: 32
Size of section headers: 8 (bytes)
Number of section headers: 40
Section header string table index: 24
readelf: Error: The e_shentsize field in the ELF header is less than the size of an ELF section header
readelf: Warning: The e_phentsize field in the ELF header is larger than the size of an ELF program header
readelf: Error: the PHDR segment is not covered by a LOAD segment

ELF header manual inspection
e_ident: 7f45 4c46 0101 0100 0000 0000 0000 0000
e_type: 0300
e_machine: 2800
e_version: 0100 000
e_entry: 1008 0000 3400 0000
e_phoff: efbf a41b 0200 0000
e_shoff: 0005 3400 2000 0800
e_flags: 2800 1800
e_ehsize: 1700
e_phentsize: 0600
e_phnum: 0000
e_shentizie: 3400
e_shnum: 0000
e_shstrndx: 3400
```

Unfortunately, the binary has some sections corrupted and even if we managed to make it ignore some specific headers, the sections headers were so far, impossible for us to reverse.

## Thoughts about this sample

This sample presents the same characteristics as the other samples: contact gathering, spying on phone calls and chats, getting data from other application as well. It is interesting to see Finspy putting its artifacts into another application. What is however more worrying is that fact that this was targetting a popular and well-known application.

It is unclear at this moment what and who this trojanised version of Wire was targetting and so far, no other samples alike have been identified.
