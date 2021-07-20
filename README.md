Packet Maze: Solving a CyberDefenders PCAP Puzzle with R, Zeek, and
tshark
================

-   [What is this?](#what-is-this)
-   [Let’s get this party started](#lets-get-this-party-started)
-   [Test Command Line Tool and File
    Access](#test-command-line-tool-and-file-access)
-   [PCAP Metadata](#pcap-metadata)
-   [Processing PCAPs with Zeek](#processing-pcaps-with-zeek)
    -   [Zeek Log File Helper Function](#zeek-log-file-helper-function)
-   [Processing PCAPs with `tshark`](#processing-pcaps-with-tshark)
-   [11 Quests](#11-quests)
-   [How many UDP packets were sent from `192.168.1.26` to
    `24.39.217.246`?](#how-many-udp-packets-were-sent-from-192168126-to-2439217246)
    -   [Question Setup](#question-setup)
    -   [Solving the quest with
        `tshark`](#solving-the-quest-with-tshark)
    -   [Solving the quest with R](#solving-the-quest-with-r)
-   [What is the MAC address of the system being
    monitored?](#what-is-the-mac-address-of-the-system-being-monitored)
    -   [Question Setup](#question-setup-1)
    -   [Solving the quest with
        `tshark`](#solving-the-quest-with-tshark-1)
    -   [Solving the quest with R and Zeek’s
        `conn.log`](#solving-the-quest-with-r-and-zeeks-connlog)
-   [What domain is the user looking up in packet
    15174?](#what-domain-is-the-user-looking-up-in-packet-15174)
    -   [Question Setup](#question-setup-2)
    -   [Solving the quest with
        `tshark`](#solving-the-quest-with-tshark-2)
    -   [Solving the quest with R and
        `packets`](#solving-the-quest-with-r-and-packets)
-   [What domain was the user connected to in packet
    27300?](#what-domain-was-the-user-connected-to-in-packet-27300)
    -   [Question Setup](#question-setup-3)
    -   [Solving the quest with R and
        `packets`](#solving-the-quest-with-r-and-packets-1)
-   [What is the IPv6 address of the DNS server used by
    `192.168.1.26`?](#what-is-the-ipv6-address-of-the-dns-server-used-by-192168126)
    -   [Question Setup](#question-setup-4)
    -   [Solving the quest with R and Zeek
        `conn.log`](#solving-the-quest-with-r-and-zeek-connlog)
-   [What is the FTP password?](#what-is-the-ftp-password)
    -   [Question Setup](#question-setup-5)
    -   [Solving the quest with R and Zeek
        `ftp.log`](#solving-the-quest-with-r-and-zeek-ftplog)
-   [What is the first TLS 1.3 client random that was used to establish
    a connection with
    `protonmail.com`?](#what-is-the-first-tls-13-client-random-that-was-used-to-establish-a-connection-with-protonmailcom)
    -   [Question Setup](#question-setup-6)
    -   [Solving the quest with `tshark` custom
        filters](#solving-the-quest-with-tshark-custom-filters)
    -   [Solving the quest with R and `tshark` custom
        filters](#solving-the-quest-with-r-and-tshark-custom-filters)
-   [What is the server certificate public key that was used in TLS
    session:
    `da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4ff`?](#what-is-the-server-certificate-public-key-that-was-used-in-tls-session-da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4ff)
    -   [Question Setup](#question-setup-7)
    -   [Solving the quest with `tshark` custom filters (and a *wee* bit
        of R)](#solving-the-quest-with-tshark-custom-filters-and-a-wee-bit-of-r)
-   [What time was a non-standard folder created on the FTP server on
    the 20th of
    April?](#what-time-was-a-non-standard-folder-created-on-the-ftp-server-on-the-20th-of-april)
    -   [Question Setup](#question-setup-8)
    -   [Solving the quest with `tshark` custom filters (and a *wee* bit
        of R)](#solving-the-quest-with-tshark-custom-filters-and-a-wee-bit-of-r-1)
-   [What country is the MAC address of the FTP server registered
    in?](#what-country-is-the-mac-address-of-the-ftp-server-registered-in)
    -   [Question Setup](#question-setup-9)
    -   [Solving the quest with Zeek `conn.log`, `ftp.log`, and
        R](#solving-the-quest-with-zeek-connlog-ftplog-and-r)
-   [What was the camera model name used to take picture
    `20210429_152157.jpg`?](#what-was-the-camera-model-name-used-to-take-picture-20210429_152157jpg)
    -   [Question Setup](#question-setup-10)
    -   [Solving the quest with Zeek `ftp.log`, `tshark` filters, and
        R](#solving-the-quest-with-zeek-ftplog-tshark-filters-and-r)

Not all data is ‘big’ nor do all data-driven cybersecurity projects
require advanced modeling capabilities. Sometimes you just need to
dissect some network packet capture (PCAP) data and don’t want to click
through a GUI to get the job done. This short book works through the
questions in [CyberDefenders Lab
#68](https://cyberdefenders.org/labs/68) to show how you can get the
[Zeek open source network security tool](https://zeek.org/), [`tshark`
command-line PCAP analysis Swiss army
knife](https://www.wireshark.org/docs/man-pages/tshark.html), and
[R](https://www.r-project.org/) (via
[RStudio](https://www.rstudio.com/)) working together.

## What is this?

A stripped down version of the examples from [the
ebook](https://rud.is/books/packet-maze/).

## Let’s get this party started

``` r
library(glue, include.only = "glue")
library(jsonlite, include.only = "fromJSON")
library(stringi, include.only = c("stri_replace_all_regex", "stri_replace_all_fixed", "stri_detect_fixed", "stri_trim_both"))
library(exif, include.only = "read_exif")
library(sf)
```

    ## Linking to GEOS 3.9.1, GDAL 3.2.1, PROJ 7.2.1

``` r
library(magick, include.only = "image_read")
```

    ## Linking to ImageMagick 6.9.11.57
    ## Enabled features: cairo, fontconfig, freetype, heic, lcms, pango, raw, rsvg, webp
    ## Disabled features: fftw, ghostscript, x11

``` r
library(MACtools)
library(tidyverse)
```

## Test Command Line Tool and File Access

Now we’ll see if `zeek` and `tshark` are available via R:

``` r
system("zeek -v", intern = TRUE) # use the path to your own Zeek installation or ensure it's on the system PATH
```

    ## [1] "zeek version 4.0.3"

``` r
system("tshark -v", intern = TRUE)  # use the path to your own tshark installation or ensure it's on the system PATH
```

    ##  [1] "TShark (Wireshark) 3.4.7 (Git commit e42cbf6a415f)"                                    
    ##  [2] ""                                                                                      
    ##  [3] "Copyright 1998-2021 Gerald Combs <gerald@wireshark.org> and contributors."             
    ##  [4] "License GPLv2+: GNU GPL version 2 or later <https://www.gnu.org/licenses/gpl-2.0.html>"
    ##  [5] "This is free software; see the source for copying conditions. There is NO"             
    ##  [6] "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."           
    ##  [7] ""                                                                                      
    ##  [8] "Compiled (64-bit) with libpcap, without POSIX capabilities, with GLib 2.68.3,"         
    ##  [9] "with zlib 1.2.11, with SMI 0.5.0, with c-ares 1.17.1, without Lua, with GnuTLS"        
    ## [10] "3.6.16 and PKCS #11 support, with Gcrypt 1.9.3, with MIT Kerberos, with MaxMind"       
    ## [11] "DB resolver, with nghttp2 1.43.0, without brotli, without LZ4, without"                
    ## [12] "Zstandard, without Snappy, with libxml2 2.9.4."                                        
    ## [13] ""                                                                                      
    ## [14] "Running on macOS 12.0, build 21A5268h (Darwin 21.0.0), with 16384 MB of physical"      
    ## [15] "memory, with locale en_US.UTF-8, with libpcap version 1.9.1, with GnuTLS 3.6.16,"      
    ## [16] "with Gcrypt 1.9.3, with zlib 1.2.11, binary plugins supported (0 loaded)."             
    ## [17] ""                                                                                      
    ## [18] "Built using clang Apple LLVM 12.0.5 (clang-1205.0.22.9)."

And make sure the PCAP is in there (you’ll need to provide this from
[the challenge](https://cyberdefenders.org/labs/68)).

``` r
list.files("maze")
```

    ##  [1] "conn.log"          "dns.log"           "files.log"        
    ##  [4] "ftp-q1.json"       "ftp.log"           "hosts.txt"        
    ##  [7] "http.log"          "maze.pcapng"       "maze.txt"         
    ## [10] "packet_filter.log" "proton-q.json"     "ssl.log"          
    ## [13] "tunnel.log"        "weird.log"         "x509.log"

## PCAP Metadata

We can get an overview of the PCAP file contents with the [`capinfos`
utility](https://tshark.dev/analyze/get_info/capinfos/) that comes along
for the ride with `tshark`:

``` r
cat(system("capinfos maze/maze.pcapng", intern=TRUE), sep="\n")
```

    ## File name:           maze/maze.pcapng
    ## File type:           Wireshark/... - pcapng
    ## File encapsulation:  Ethernet
    ## File timestamp precision:  nanoseconds (9)
    ## Packet size limit:   file hdr: (not set)
    ## Number of packets:   45k
    ## File size:           38MB
    ## Data size:           36MB
    ## Capture duration:    450.466647147 seconds
    ## First packet time:   2021-04-29 21:00:51.031550031
    ## Last packet time:    2021-04-29 21:08:21.498197178
    ## Data byte rate:      82kBps
    ## Data bit rate:       656kbps
    ## Average packet size: 821.02 bytes
    ## Average packet rate: 99 packets/s
    ## SHA256:              3cc2061959afb116aeedce2736809f28236b96e20b89b4199194f4a30a0802ba
    ## RIPEMD160:           e278720f93a6d58b45d1614877eb92b91ef0a684
    ## SHA1:                0a40bcf2c2329ddf72bd864f05855314cb76514d
    ## Strict time order:   False
    ## Capture hardware:    Intel(R) Core(TM) i7-10510U CPU @ 1.80GHz (with SSE4.2)
    ## Capture oper-sys:    Linux 5.4.0-72-generic
    ## Capture application: Dumpcap (Wireshark) 3.2.3 (Git v3.2.3 packaged as 3.2.3-1)
    ## Number of interfaces in file: 1
    ## Interface #0 info:
    ##                      Name = wlo1
    ##                      Encapsulation = Ethernet (1 - ether)
    ##                      Capture length = 262144
    ##                      Time precision = nanoseconds (9)
    ##                      Time ticks per second = 1000000000
    ##                      Time resolution = 0x09
    ##                      Operating system = Linux 5.4.0-72-generic
    ##                      Number of stat entries = 1
    ##                      Number of packets = 45024

## Processing PCAPs with Zeek

We’ll first generate a series of standard Zeek “log” files that are
packet-capture feature-specific structured files. We’ve enabled the
`mac-logging` rules so certain log files will also contain [MAC
addresses](https://en.wikipedia.org/wiki/MAC_address) of the nodes
(since some questions ask about those).

``` r
wd <- getwd()
setwd("maze")
system("zeek --no-checksums --readfile maze.pcapng policy/protocols/conn/mac-logging")
setwd(wd)
```

We can see if that worked by getting a directory listing:

``` r
list.files("maze")
```

    ##  [1] "conn.log"          "dns.log"           "files.log"        
    ##  [4] "ftp-q1.json"       "ftp.log"           "hosts.txt"        
    ##  [7] "http.log"          "maze.pcapng"       "maze.txt"         
    ## [10] "packet_filter.log" "proton-q.json"     "ssl.log"          
    ## [13] "tunnel.log"        "weird.log"         "x509.log"

Each log file has different information based upon what was contained in
the PCAP. For our example, these are the logs that were generated.
Follow the links to learn more about what is in each of them.

-   `conn.log`: [TCP/UDP/ICMP
    connections](https://docs.zeek.org/en/master/logs/conn.html)
-   `dns.log`: [DNS
    Activity](https://docs.zeek.org/en/master/logs/dns.html)
-   `files.log`: [File analysis
    results](https://docs.zeek.org/en/master/logs/files.html)
-   `ftp.log`: [FTP
    activity](https://docs.zeek.org/en/master/logs/ftp.html)
-   `http.log`: [HTTP requests and
    replies](https://docs.zeek.org/en/master/logs/http.html)
-   `packet_filter.log`: [List packet filters that were
    applied](https://docs.zeek.org/en/master/scripts/base/frameworks/packet-filter/main.zeek.html)
-   `ssl.log`: [SSL/TLS handshake
    info](https://docs.zeek.org/en/master/logs/ssl.html)
-   `tunnel.log`: [Tunneling protocol
    events](https://docs.zeek.org/en/master/logs/tunnel.html)
-   `weird.log`: [Unexpected network-level
    activity](https://docs.zeek.org/en/master/logs/weird-and-notice.html)
-   `x509.log`: [X.509 certificate
    info](https://docs.zeek.org/en/master/logs/x509.html)

### Zeek Log File Helper Function

Zeek logs are well-structured files that, by default, have a very
informative header:

``` r
read_lines("maze/conn.log", n_max = 8) 
```

    ## [1] "#separator \\x09"                                                                                                                                                                                                                                                         
    ## [2] "#set_separator\t,"                                                                                                                                                                                                                                                        
    ## [3] "#empty_field\t(empty)"                                                                                                                                                                                                                                                    
    ## [4] "#unset_field\t-"                                                                                                                                                                                                                                                          
    ## [5] "#path\tconn"                                                                                                                                                                                                                                                              
    ## [6] "#open\t2021-07-20-15-51-37"                                                                                                                                                                                                                                               
    ## [7] "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\torig_l2_addr\tresp_l2_addr"
    ## [8] "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\tstring\tstring"

As such, having a small helper function to deal with assigning valid
column names and skipping past the header will be helpful:

``` r
read_zeek_log <- function(path) {
  
  # get column names
  read_lines(path[1], n_max = 7) %>% 
    last() %>% 
    strsplit("\t") %>% 
    unlist() %>% 
    tail(-1) -> cols
  
  read_tsv(path[1], col_names = cols, comment = "#")  
  
  suppressMessages(
    read_tsv(
      file = path[1], 
      col_names = cols, 
      comment = "#" # read, skipping header
    )
  )
  
}
```

## Processing PCAPs with `tshark`

Zeek is great, but some questions ask about packet numbers (and, it’s
often helpful to have packet-level information available in general).
For this, we’ll turn to `tshark` to generate a lightweight delimited
text file with basic, per-packet metadata:

``` r
system("tshark -T tabs -r maze/maze.pcapng > maze/maze.txt")
```

Let’s take a look at at the first few lines:

``` r
read_lines("maze/maze.txt", n_max = 10)
```

    ##  [1] "    1\t0.000000000\t192.168.1.26\t→\t13.107.21.200\tTCP\t74\t33066 → 443 [SYN] Seq=0 Win=65330 Len=0 MSS=1390 SACK_PERM=1 TSval=1979376479 TSecr=0 WS=128"                     
    ##  [2] "    2\t0.004073155\t173.223.18.66\t→\t192.168.1.26\tTCP\t66\t80 → 51754 [FIN, ACK] Seq=1 Ack=1 Win=17 Len=0 TSval=4167144401 TSecr=3610316592"                                 
    ##  [3] "    3\t0.004680329\t192.168.1.26\t→\t173.223.18.66\tTCP\t66\t51754 → 80 [FIN, ACK] Seq=1 Ack=2 Win=502 Len=0 TSval=3610347326 TSecr=4167144401"                                
    ##  [4] "    4\t0.068286008\t192.168.1.26\t→\t13.107.21.200\tTLSv1.2\t525\tApplication Data"                                                                                            
    ##  [5] "    5\t0.068326815\t192.168.1.26\t→\t13.107.21.200\tTLSv1.2\t624\tApplication Data"                                                                                            
    ##  [6] "    6\t0.140702265\t192.168.1.26\t→\t13.107.21.200\tTLSv1.2\t104\tApplication Data"                                                                                            
    ##  [7] "    7\t0.143929532\t13.107.21.200\t→\t192.168.1.26\tTCP\t74\t443 → 33066 [SYN, ACK] Seq=0 Ack=1 Win=14600 Len=0 MSS=1380 SACK_PERM=1 TSval=4167144541 TSecr=1979376479 WS=1024"
    ##  [8] "    8\t0.144015466\t192.168.1.26\t→\t13.107.21.200\tTCP\t66\t33066 → 443 [ACK] Seq=1 Ack=1 Win=65408 Len=0 TSval=1979376623 TSecr=4167144541"                                  
    ##  [9] "    9\t0.145324645\t192.168.1.26\t→\t13.107.21.200\tTLSv1\t191\tClient Hello"                                                                                                  
    ## [10] "   10\t0.148841745\t173.223.18.66\t→\t192.168.1.26\tTCP\t66\t80 → 51754 [ACK] Seq=2 Ack=2 Win=17 Len=0 TSval=4167144541 TSecr=3610347326"

This is a straightforward tab separated values (TSV) file without a
header, which means using something like `readr::read_tsv()` will work
fine, but column names will be `X1`, `X2`, etc. We could leave them like
that since this is just a small exercise and we won’t be using this
packet information much, but it’s nicer to work with column names that
mean something, so we’ll assign the following names when we read in the
file:

-   `packet_num`: Packet number
-   `ts`: Time (relative to the start of the capture) the packet was
    seen
-   `src`: Source address
-   Kinda useless arrow that we’ll leave out of the data frame
-   `dst`: Destination address
-   `proto`: Protocol
-   `length`: Packet length (bytes)
-   `info`: General information about the packet

We can squeeze a more up-front metadata that may come in handy later on
using the `tshark` `-z` option which lets us gather different
statistics. Specifically, we’ll generate a list of IP address → host
mappings (from the DNS queries that were performed during the session) :

``` r
system("tshark -q -z hosts -r maze/maze.pcapng > maze/hosts.txt") 
```

This is yet-another plaintext, tab-separated file with comments and no
header line (we’ll read this in and look at it later)

## 11 Quests

The story setup for these exercises is that we are analysts working for
a security service provider and have been tasked with analyzing a packet
capture for a customer’s employee whose network activity has been
monitored for a while. The company suspects this individual is a
possible insider threat.

The set of questions appears to be randomized on the CyberDefenders site
(likely to prevent blind copy/pasting from solution sets like this).
We’re going to tackle them in the following order to create a more
logical flow.

1.  How many UDP packets were sent from `192.168.1.26` to
    `24.39.217.246`?
2.  What is the MAC address of the system being monitored?
3.  What domain is the user looking up in packet 15174?
4.  What domain was the user connected to in packet 27300?
5.  What is the IPv6 address of the DNS server used by `192.168.1.26`?
6.  What is the FTP password?
7.  What is the first TLS 1.3 client random that was used to establish a
    connection with `protonmail.com`?
8.  What is the server certificate public key that was used in TLS
    session:
    `da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4ff`?
9.  What time was a non-standard folder created on the FTP server on the
    20th of April?
10. What country is the MAC address of the FTP server registered in?
11. What was the camera model name used to take picture
    `20210429_152157.jpg`?

The challenge setup does not state this overtly, but the target of our
network analysis is the user activity associated with the IP address
`192.168.1.26`.

To start, we’ll read in the packet information file we generated with
`tshark`:

``` r
packet_cols <- c("packet_num", "ts", "src", "discard", "dst", "proto", "length", "info")

read_tsv(
  file = "maze/maze.txt",
  col_names = packet_cols,
  col_types = "ddccccdc"
) %>% 
  select(-discard) %>% 
  glimpse() -> packets
```

    ## Rows: 45,024
    ## Columns: 7
    ## $ packet_num <dbl> 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, …
    ## $ ts         <dbl> 0.000000000, 0.004073155, 0.004680329, 0.068286008, 0.06832…
    ## $ src        <chr> "192.168.1.26", "173.223.18.66", "192.168.1.26", "192.168.1…
    ## $ dst        <chr> "13.107.21.200", "192.168.1.26", "173.223.18.66", "13.107.2…
    ## $ proto      <chr> "TCP", "TCP", "TCP", "TLSv1.2", "TLSv1.2", "TLSv1.2", "TCP"…
    ## $ length     <dbl> 74, 66, 66, 525, 624, 104, 74, 66, 191, 66, 66, 66, 66, 66,…
    ## $ info       <chr> "33066 → 443 [SYN] Seq=0 Win=65330 Len=0 MSS=1390 SACK_PERM…

``` r
packets
```

    ## # A tibble: 45,024 x 7
    ##    packet_num      ts src      dst      proto length info                       
    ##         <dbl>   <dbl> <chr>    <chr>    <chr>  <dbl> <chr>                      
    ##  1          1 0       192.168… 13.107.… TCP       74 33066 → 443 [SYN] Seq=0 Wi…
    ##  2          2 0.00407 173.223… 192.168… TCP       66 80 → 51754 [FIN, ACK] Seq=…
    ##  3          3 0.00468 192.168… 173.223… TCP       66 51754 → 80 [FIN, ACK] Seq=…
    ##  4          4 0.0683  192.168… 13.107.… TLSv…    525 Application Data           
    ##  5          5 0.0683  192.168… 13.107.… TLSv…    624 Application Data           
    ##  6          6 0.141   192.168… 13.107.… TLSv…    104 Application Data           
    ##  7          7 0.144   13.107.… 192.168… TCP       74 443 → 33066 [SYN, ACK] Seq…
    ##  8          8 0.144   192.168… 13.107.… TCP       66 33066 → 443 [ACK] Seq=1 Ac…
    ##  9          9 0.145   192.168… 13.107.… TLSv1    191 Client Hello               
    ## 10         10 0.149   173.223… 192.168… TCP       66 80 → 51754 [ACK] Seq=2 Ack…
    ## # … with 45,014 more rows

Now we’ll get an overview of the activity by looking at the number of
packets originating from the target we’re investigating to each distinct
host by protocol:

``` r
packets %>% 
  filter(src == "192.168.1.26") %>% 
  count(src, dst, proto, sort=TRUE) %>% 
  print(n=20) # limiting to 20 rows of output for brevity; IRL you'd likely want to see them all
```

    ## # A tibble: 146 x 4
    ##    src          dst             proto        n
    ##    <chr>        <chr>           <chr>    <int>
    ##  1 192.168.1.26 172.67.162.206  TCP      17942
    ##  2 192.168.1.26 192.168.1.20    FTP-DATA  8568
    ##  3 192.168.1.26 185.70.41.130   TCP       2307
    ##  4 192.168.1.26 23.51.191.35    TCP       1185
    ##  5 192.168.1.26 185.70.41.35    TCP        687
    ##  6 192.168.1.26 159.65.89.65    TCP        394
    ##  7 192.168.1.26 142.250.190.132 QUIC       361
    ##  8 192.168.1.26 23.51.191.35    TLSv1.2    332
    ##  9 192.168.1.26 35.186.220.63   TCP        161
    ## 10 192.168.1.26 13.107.21.200   TCP        133
    ## 11 192.168.1.26 24.35.154.189   UDP        113
    ## 12 192.168.1.26 192.168.1.20    TCP         85
    ## 13 192.168.1.26 52.137.103.130  TCP         83
    ## 14 192.168.1.26 185.70.41.130   TLSv1.3     67
    ## 15 192.168.1.26 104.21.89.171   QUIC        65
    ## 16 192.168.1.26 192.168.0.44    UDP         60
    ## 17 192.168.1.26 204.79.197.200  TCP         47
    ## 18 192.168.1.26 52.137.103.130  TLSv1.2     43
    ## 19 192.168.1.26 13.107.246.254  TCP         39
    ## 20 192.168.1.26 192.168.1.20    FTP         38
    ## # … with 126 more rows

as well as the overall protocol use distribution:

``` r
packets %>% 
  count(proto, sort=TRUE) %>% 
  print(n=nrow(.))
```

    ## # A tibble: 20 x 2
    ##    proto        n
    ##    <chr>    <int>
    ##  1 TCP      28933
    ##  2 FTP-DATA  8573
    ##  3 TLSv1.3   3269
    ##  4 TLSv1.2   1772
    ##  5 QUIC      1557
    ##  6 UDP        234
    ##  7 DNS        163
    ##  8 ICMPv6     152
    ##  9 IPv6       109
    ## 10 FTP         88
    ## 11 ARP         72
    ## 12 TLSv1       31
    ## 13 NBNS        21
    ## 14 SSLv2       18
    ## 15 HTTP        17
    ## 16 ICMP         7
    ## 17 IGMPv2       4
    ## 18 EAPOL        2
    ## 19 OCSP         1
    ## 20 SSL          1

We can further count the total number of network hosts contacted:

``` r
packets %>% 
  filter(
    src == "192.168.1.26",
    dst != "192.168.1.26"
  ) %>% 
  distinct(dst) %>% 
  count()
```

    ## # A tibble: 1 x 1
    ##       n
    ##   <int>
    ## 1    70

You are encouraged to poke around this data frame with some of the
concepts you may have seen in
[R4DS](https://r4ds.had.co.nz/wrangle-intro.html) before jumping into
the first quest.

## How many UDP packets were sent from `192.168.1.26` to `24.39.217.246`?

### Question Setup

We’ve been asked to determine how many [UDP
packets]((https://datatracker.ietf.org/doc/html/rfc768):) were sent from
`192.168.1.26` to `24.39.217.246`. You use UDP every day (well, your
browsers/devices do) when you lookup website addresses (i.e. make
traditional DNS queries) and even visit some websites since super fancy
ones use [HTTP/3 or
QUIC](https://quicwg.org/base-drafts/draft-ietf-quic-http.html)
protocols to speedup web sessions. This makes knowing how to find UDP
information in packet captures a “must have” skill.

### Solving the quest with `tshark`

The truth is that we don’t really need R to answer this question since
`tshark` has a rich query filter language which lets us subset what
we’re looking for by wide array of fields.

In this case we’re looking for an IP source address (`ip.src`) of
`192.168.1.26` talking to an IP destination address (`ip.dst`) of
`24.39.217.246` speaking the UDP (`udp`) network protocol:

``` r
system("tshark -r maze/maze.pcapng '(ip.src == 192.168.1.26) and (ip.dst == 24.39.217.246) and udp'", intern = TRUE)
```

    ##  [1] "15806 128.281136434 192.168.1.26 → 24.39.217.246 UDP 94 53638 → 54150 Len=52"
    ##  [2] "15808 128.283606894 192.168.1.26 → 24.39.217.246 UDP 94 51601 → 54150 Len=52"
    ##  [3] "15825 130.239091258 192.168.1.26 → 24.39.217.246 UDP 94 53638 → 54150 Len=52"
    ##  [4] "15851 132.241685345 192.168.1.26 → 24.39.217.246 UDP 94 53638 → 54150 Len=52"
    ##  [5] "15865 135.324998370 192.168.1.26 → 24.39.217.246 UDP 94 53638 → 54150 Len=52"
    ##  [6] "15942 137.223543961 192.168.1.26 → 24.39.217.246 UDP 94 53638 → 54150 Len=52"
    ##  [7] "16095 139.223629695 192.168.1.26 → 24.39.217.246 UDP 94 53638 → 54150 Len=52"
    ##  [8] "16695 143.331929739 192.168.1.26 → 24.39.217.246 UDP 94 53638 → 54150 Len=52"
    ##  [9] "16810 145.217958711 192.168.1.26 → 24.39.217.246 UDP 94 53638 → 54150 Len=52"
    ## [10] "16955 147.222253195 192.168.1.26 → 24.39.217.246 UDP 94 53638 → 54150 Len=52"

If you’re on a system with `wc` (word/char/line count utility — Windows
folks can use [WSL
2](https://docs.microsoft.com/en-us/windows/wsl/wsl2-faq)) you can pipe
that output to said utility and end up with the value `10`.

### Solving the quest with R

#### Using the `tshark` `packets` data

We already have `packets` in memory from above and can use a `{dplyr}`
chain with essentially the same query we used in `tshark`:

``` r
packets %>% 
  filter(
    src == "192.168.1.26", 
    dst == "24.39.217.246",
    proto == "UDP"
  ) %>% 
  count()
```

    ## # A tibble: 1 x 1
    ##       n
    ##   <int>
    ## 1    10

We can also use “classic R” idioms (along with the new, built-in/native
pipe symbol `|>`) if we’re in a retro-ish mood:

``` r
packets |>
  subset(
    (src == "192.168.1.26") &
      (dst == "24.39.217.246") &
      (proto == "UDP")    
  ) |>
  nrow()
```

    ## [1] 10

#### Using Zeek `conn.log` data

We can arrive at the same answer by examining the Zeek `conn.log` data
using a similar technique. The Zeek `src`/`dst` equivalents are
`id.orig_h`/`id.resp_h` (`proto` is the same but the contents are
lowercase), and Zeek’s `conn.log` has an `orig_pkts` field for each
record which is the number of packets that the originator sent, which
means we just need to sum those up to get our answer.

``` r
# read in the Zeek conn.log — this will now be in memory for future reference
(conn <- read_zeek_log("maze/conn.log"))
```

    ## 
    ## ── Column specification ────────────────────────────────────────────────────────
    ## cols(
    ##   .default = col_character(),
    ##   ts = col_double(),
    ##   id.orig_p = col_double(),
    ##   id.resp_p = col_double(),
    ##   missed_bytes = col_double(),
    ##   orig_pkts = col_double(),
    ##   orig_ip_bytes = col_double(),
    ##   resp_pkts = col_double(),
    ##   resp_ip_bytes = col_double()
    ## )
    ## ℹ Use `spec()` for the full column specifications.

    ## # A tibble: 12,443 x 23
    ##         ts uid    id.orig_h id.orig_p id.resp_h id.resp_p proto service duration
    ##      <dbl> <chr>  <chr>         <dbl> <chr>         <dbl> <chr> <chr>   <chr>   
    ##  1  1.62e9 Cd1kC… 192.168.…     51754 173.223.…        80 tcp   -       0.000607
    ##  2  1.62e9 CSUav… 192.168.…     36116 192.168.…        53 udp   dns     0.191884
    ##  3  1.62e9 CoIJj… 192.168.…     33066 13.107.2…       443 tcp   ssl     10.3804…
    ##  4  1.62e9 Cp3g8… 192.168.…     52064 192.168.…        53 udp   dns     0.068408
    ##  5  1.62e9 CRark… 192.168.…     58432 192.168.…        53 udp   dns     0.081218
    ##  6  1.62e9 CEA3J… 192.168.…     45191 192.168.…        53 udp   dns     0.133955
    ##  7  1.62e9 CcAdc… 192.168.…     59660 192.168.…        53 udp   dns     0.097726
    ##  8  1.62e9 CYgYp… 192.168.…     33078 13.107.2…       443 tcp   -       0.138868
    ##  9  1.62e9 CZhaP… 192.168.…     54444 192.168.…        53 udp   dns     -       
    ## 10  1.62e9 CLk9B… 192.168.…     54764 173.223.…       443 tcp   -       0.151084
    ## # … with 12,433 more rows, and 14 more variables: orig_bytes <chr>,
    ## #   resp_bytes <chr>, conn_state <chr>, local_orig <chr>, local_resp <chr>,
    ## #   missed_bytes <dbl>, history <chr>, orig_pkts <dbl>, orig_ip_bytes <dbl>,
    ## #   resp_pkts <dbl>, resp_ip_bytes <dbl>, tunnel_parents <chr>,
    ## #   orig_l2_addr <chr>, resp_l2_addr <chr>

``` r
conn %>% 
  filter(
    (id.orig_h == "192.168.1.26"),
    (id.resp_h == "24.39.217.246"),
    (proto == "udp")
  ) %>% 
  count(
    wt = orig_pkts
  )
```

    ## # A tibble: 1 x 1
    ##       n
    ##   <dbl>
    ## 1    10

## What is the MAC address of the system being monitored?

### Question Setup

In this quest, we’ve been tasked with identifying the [MAC
address](https://en.wikipedia.org/wiki/MAC_address) of the system being
monitored. (NOTE: From Chapter 4 we know the system being monitored is
`192.168.1.26`). These are the addresses assigned to the network
interface hardware and can be useful in identifying system types. While
these addresses [can be
forged](https://en.wikipedia.org/wiki/MAC_spoofing), they are still
useful (especially so if an analysis can determine that one or more MAC
addresses were indeed spoofed) and it is good to have an understanding
of how to work with them in an analysis.

### Solving the quest with `tshark`

We can limit the output fields `tshark` displays via the `-Tfields`
option and specifying the fields we want by adding `-e FIELD-NAME`
options.

The MAC address is the `eth.src` field and we can use an additional
display filter — `frame.number` — to limit the output to the first frame
of the subset we’re filtering on:

``` r
system("tshark -r maze/maze.pcapng -nn -e ip.src -e eth.src -Tfields '(ip.src == 192.168.1.26) and (frame.number == 1)'", intern=TRUE)
```

    ## [1] "192.168.1.26\tc8:09:a8:57:47:93"

### Solving the quest with R and Zeek’s `conn.log`

Remember back when we made sure that Zeek included MAC addresses when it
generated log files? This question is one reason we did that. The `conn`
data frame has `orig_l2_addr` and `resp_l2_addr` columns for the source
and destination MAC addresses.

We can perform another, similar filter to find out the MAC address for
the target:

``` r
conn %>% 
  filter(id.orig_h == "192.168.1.26") %>% 
  distinct(orig_l2_addr)
```

    ## # A tibble: 1 x 1
    ##   orig_l2_addr     
    ##   <chr>            
    ## 1 c8:09:a8:57:47:93

``` r
conn |>
  subset(
    id.orig_h == "192.168.1.26", # our target
    select = orig_l2_addr,       # select the MAC address field
    drop = TRUE                  # reduce the output to a vector
  ) %>%
  unique()
```

    ## [1] "c8:09:a8:57:47:93"

## What domain is the user looking up in packet 15174?

### Question Setup

We’re finally getting into some interesting areas with our latest quest
to discover what domain the user is looking up in packet `15174`. PCAPs
hold the entire conversation between a source and destination, including
the contents of the data being exchanged. If encryption is not in the
way it is possible to reconstruct that data (if the formats are known)
and see what was being exchanged. Unencrypted DNS queries have a
longstanding format that `tshark`, Zeek, and *many* other tools know how
to decode.

This is a good quest to work through to see how to select specific
packets and look at their contents.

### Solving the quest with `tshark`

We learned about `frame.number` in the previous chapter and can use that
knowledge to quickly arrive at the answer:

``` r
system("tshark -r maze/maze.pcapng frame.number == 15174", intern=TRUE)
```

    ## [1] "15174 126.315295572 fe80::b011:ed39:8665:3b0a → fe80::c80b:adff:feaa:1db7 DNS 104 Standard query 0x1ad5 A www.7-zip.org OPT"

### Solving the quest with R and `packets`

We can perform nearly the same thing with the `packets` data frame in
many ways. First with `{dplyr}`:

``` r
packets %>% 
  filter(
    packet_num == 15174
  ) %>% 
  select(info)
```

    ## # A tibble: 1 x 1
    ##   info                                     
    ##   <chr>                                    
    ## 1 Standard query 0x1ad5 A www.7-zip.org OPT

We also rely on the fact that `packet_num` is sequential starting with
1, so we can just index the data frame directly:

``` r
packets[15174, "info", drop=TRUE] 
```

    ## [1] "Standard query 0x1ad5 A www.7-zip.org OPT"

``` r
packets$info[15174]
```

    ## [1] "Standard query 0x1ad5 A www.7-zip.org OPT"

## What domain was the user connected to in packet 27300?

### Question Setup

True to the name of this challenge we have to make a few twists and
turns to figure out what domain the user connected to in packet 27300?
This involves selecting the packet and grabbing the destination IP, then
looking that up in other metadata we can generate. This will help build
or refresh the use of a common idiom in cybersecurity analyses: using
multiple data sources to arrive at an an answer.

### Solving the quest with R and `packets`

We finally have an opportunity to use the `hosts.txt` file we generated
in Chapter 2! And, while we could do a few `tshark` standalone command
line machinations to solve this quest, it doesn’t make much sense to
since we have to deal with multiple calls, already have the data we
need, and would have to use other command line tools to truly “solve” it
well with “just” `tshark`.

``` r
# read in our hosts/ip file
read_tsv(
  file = "maze/hosts.txt",
  col_names = c("ip", "hostname"), 
  col_types = "cc",
  skip = 3
) -> hosts

packets %>% 
  filter(packet_num == 27300) %>% 
  select(ip = dst) %>% 
  left_join(hosts)
```

    ## Joining, by = "ip"

    ## # A tibble: 1 x 2
    ##   ip             hostname    
    ##   <chr>          <chr>       
    ## 1 172.67.162.206 dfir.science

Old-school R follows the same idiom:

``` r
packets |>
  subset(
    packet_num == 27300,
    select = dst
  ) |>
  merge(
    hosts, 
    by.x = "dst", 
    by.y = "ip"
  )
```

    ##              dst     hostname
    ## 1 172.67.162.206 dfir.science

## What is the IPv6 address of the DNS server used by `192.168.1.26`?

### Question Setup

Our maze is getting even twistier now as we seek out the IPv6 address of
the DNS server used by `192.168.1.26`? If we don’t read the question
thoroughly it is possible to arrive at a wrong answer by forgetting it
asked about the DNS server the client is using and not the client
itself.

This quest also underscores a critical fact about modern computing
environments: IPv6 adoption is increasing and many (if not most) hosts —
at least on internal networks — use both IPv4 and IPv6 addresses at the
same time. Knowing the various addresses a given host (idenfitied via
MAC address) has/had is crucial to tracing activity. Forgetting that
IPv6 can be in play could be a costly mistake IRL.

### Solving the quest with R and Zeek `conn.log`

Again, while we could do a few `tshark` standalone command line
machinations to solve this quest, it doesn’t make much sense to since we
have to deal with multiple calls, already have the data we need, and
would have to use other command line tools to truly “solve” it well with
“just” `tshark`.

We first need to find (in `conn`) the DNS traffic for our target host,
then take the MAC address of the IP address it is talking to and then
re-look for that in `conn`:

``` r
conn %>% 
  filter(
    id.orig_h == "192.168.1.26", 
    service == "dns"
  ) %>% 
  select(orig_l2_addr = resp_l2_addr) %>% 
  left_join(conn) %>% 
  filter(!is.na(id.orig_h)) %>% 
  distinct(id.orig_h)
```

    ## Joining, by = "orig_l2_addr"

    ## # A tibble: 1 x 1
    ##   id.orig_h                
    ##   <chr>                    
    ## 1 fe80::c80b:adff:feaa:1db7

Base R is, again, similar:

``` r
conn %>% 
  subset(
    id.orig_h == "192.168.1.26" & service == "dns",
    select = resp_l2_addr
  ) |>
  merge(
    conn,
    by.x = "resp_l2_addr",
    by.y = "orig_l2_addr"
  ) |>
  subset(
    !is.na(id.orig_h),
    select = id.orig_h,
    drop = TRUE
  ) %>% 
  unique()
```

    ## [1] "fe80::c80b:adff:feaa:1db7"

## What is the FTP password?

### Question Setup

We mentioned in a previous chapter that PCAPs contain all the details of
network exchanges between hosts. When this information is not encrypted,
anyone on the network, or in possession of a capture such as this, can
see the payloads. This quest helps underscore how terribly insecure bare
FTP is. However, since FTP will be around for some time to come, knowing
where and how to look for answers to FTP questions will be a necessary
skill.

### Solving the quest with R and Zeek `ftp.log`

This one is almost too easy. Because we used Zeek to pre-process the
PCAP file, we have all the FTP session information available in the
`ftp.log` log file. One of the fields in that file is (you guessed it)
`password`:

``` r
# read in the Zeek ftp.log — this will now be in memory for future reference

(ftp <- read_zeek_log("maze/ftp.log"))
```

    ## 
    ## ── Column specification ────────────────────────────────────────────────────────
    ## cols(
    ##   ts = col_double(),
    ##   uid = col_character(),
    ##   id.orig_h = col_character(),
    ##   id.orig_p = col_double(),
    ##   id.resp_h = col_character(),
    ##   id.resp_p = col_double(),
    ##   user = col_character(),
    ##   password = col_character(),
    ##   command = col_character(),
    ##   arg = col_character(),
    ##   mime_type = col_character(),
    ##   file_size = col_character(),
    ##   reply_code = col_double(),
    ##   reply_msg = col_character(),
    ##   data_channel.passive = col_character(),
    ##   data_channel.orig_h = col_character(),
    ##   data_channel.resp_h = col_character(),
    ##   data_channel.resp_p = col_character(),
    ##   fuid = col_character()
    ## )

    ## # A tibble: 10 x 19
    ##         ts uid    id.orig_h id.orig_p id.resp_h id.resp_p user  password command
    ##      <dbl> <chr>  <chr>         <dbl> <chr>         <dbl> <chr> <chr>    <chr>  
    ##  1  1.62e9 C8Dj3… 192.168.…     48794 192.168.…        21 kali  AfricaC… PASV   
    ##  2  1.62e9 C8Dj3… 192.168.…     48794 192.168.…        21 kali  AfricaC… PASV   
    ##  3  1.62e9 CJMIN… 192.168.…     48800 192.168.…        21 kali  AfricaC… PASV   
    ##  4  1.62e9 CJMIN… 192.168.…     48800 192.168.…        21 kali  AfricaC… STOR   
    ##  5  1.62e9 CJMIN… 192.168.…     48800 192.168.…        21 kali  AfricaC… PASV   
    ##  6  1.62e9 CJMIN… 192.168.…     48800 192.168.…        21 kali  AfricaC… PASV   
    ##  7  1.62e9 CJMIN… 192.168.…     48800 192.168.…        21 kali  AfricaC… STOR   
    ##  8  1.62e9 CJMIN… 192.168.…     48800 192.168.…        21 kali  AfricaC… PASV   
    ##  9  1.62e9 CZTKO… 192.168.…     48810 192.168.…        21 kali  AfricaC… PASV   
    ## 10  1.62e9 CZTKO… 192.168.…     48810 192.168.…        21 kali  AfricaC… RETR   
    ## # … with 10 more variables: arg <chr>, mime_type <chr>, file_size <chr>,
    ## #   reply_code <dbl>, reply_msg <chr>, data_channel.passive <chr>,
    ## #   data_channel.orig_h <chr>, data_channel.resp_h <chr>,
    ## #   data_channel.resp_p <chr>, fuid <chr>

``` r
distinct(ftp, password)
```

    ## # A tibble: 1 x 1
    ##   password     
    ##   <chr>        
    ## 1 AfricaCTF2021

``` r
# or with Base R

unique(ftp$password)
```

    ## [1] "AfricaCTF2021"

## What is the first TLS 1.3 client random that was used to establish a connection with `protonmail.com`?

### Question Setup

We’ve mazed into encrypted, technical territory with our new quest to
seek out the first TLS 1.3 client random that was used to establish a
connection with `protonmail.com`? TLS (transport layer security) is what
your browser (and other clients) use to keep data away from prying eyes.
TLS connections must be setup/established through a handshake process
and we’ve been asked to pick out a certain element from the first
handshake made to a connection to ProtonMail, an end-to-end encrypted
email service hosted in Switzerland.

This quest expects us to know about this handshake and where to look for
the associated data. In the most TLS exchange algorithm (RSA) the first
message in this handshake is what is known as the “client hello”
message. Your client send a “hey there” greeting to the server, telling
it what TLS version and cipher suites it supports plus a string of
random bytes boringly known as the “client random”. This is target of
our quest.

While we’ve generated *many* files from the PCAP, we’re going to have to
poke at it again to solve this question with the least amount of
frustration. The `tshark` filters contain a cadre of [`tls`
filters](https://www.wireshark.org/docs/dfref/t/tls.html), one of which
is `tls.handshake.extensions_server_name` which can be used to search
for server names specified in the [Server Name
Indication](https://en.wikipedia.org/wiki/Server_Name_Indication) (SNI)
TLS extension field. Since this name will be in the client hello, we can
filter on it and then identify the first client random.

### Solving the quest with `tshark` custom filters

We really don’t need R at all since we can create a display filter and
choose what fields to output right on the `tshark` command line:

``` r
system("tshark -r maze/maze.pcapng -e tls.handshake.random -Tfields tls.handshake.extensions_server_name == 'protonmail.com'", intern=TRUE)
```

    ## [1] "24e92513b97a0348f733d16996929a79be21b0b1400cd7e2862a732ce7775b70"
    ## [2] "32b9d36ddc0a2cc8c46811a50114ee2425c3dbf67be6b3d76f186ef25551548a"
    ## [3] "be82534e4aaef468ac88fe15473dd429bd7c4051c7a032d51d7979f36d76fdc7"
    ## [4] "492fc3d932fb6426bb9d7a087cc5e2ae8fd4a0f6826f8736fb0f1ad225b962f4"
    ## [5] "721f28c2a407810abfdbf7d9c8be8e3f452cc80d52e6f738fa158e521ff2f20e"
    ## [6] "ddfb32c96ba450dee42f208944d96bebad751298ce3471cb8e06ee112e37493c"

The first element is the target of our quest.

### Solving the quest with R and `tshark` custom filters

TLS JSON output in `tshark` is ginormous, so filtering as much as
possible before outputting the JSON is paramount.

We’ll take a similar strategy to the pure `tshark` version above and
grab all the handshakes for Proton Mail. The `-T json` unsurprisingly
generates JSON output and you are encouraged to bring that file up in
`vim`, Sublime Text, or even pipe it through `jq` to see how complex the
structure is. We’ll do the same in R:

``` r
system("tshark -T json -r maze/maze.pcapng tls.handshake.extensions_server_name == 'protonmail.com' > maze/proton-q.json")

library(jsonlite, include.only = "fromJSON")

proton_hands <- fromJSON("maze/proton-q.json")

str(proton_hands, 3) # look at the structure of the object, only going 3 nested levels deep
```

    ## 'data.frame':    6 obs. of  4 variables:
    ##  $ _index : chr  "packets-2021-04-29" "packets-2021-04-29" "packets-2021-04-29" "packets-2021-04-29" ...
    ##  $ _type  : chr  "doc" "doc" "doc" "doc" ...
    ##  $ _score : logi  NA NA NA NA NA NA
    ##  $ _source:'data.frame': 6 obs. of  1 variable:
    ##   ..$ layers:'data.frame':   6 obs. of  5 variables:
    ##   .. ..$ frame:'data.frame': 6 obs. of  15 variables:
    ##   .. ..$ eth  :'data.frame': 6 obs. of  5 variables:
    ##   .. ..$ ip   :'data.frame': 6 obs. of  19 variables:
    ##   .. ..$ tcp  :'data.frame': 6 obs. of  24 variables:
    ##   .. ..$ tls  :'data.frame': 6 obs. of  1 variable:

We can see that each packet has many layers (and not all packets must or
will have the same layer types in a given PCAP). This data structure
contains extracted handshakes associated with the `protonmail.com` SNI,
and all of this information will be in the `tls` structure.

``` r
str(proton_hands$`_source`$layers$tls, 2)
```

    ## 'data.frame':    6 obs. of  1 variable:
    ##  $ tls.record:'data.frame':  6 obs. of  4 variables:
    ##   ..$ tls.record.content_type: chr  "22" "22" "22" "22" ...
    ##   ..$ tls.record.version     : chr  "0x00000301" "0x00000301" "0x00000301" "0x00000301" ...
    ##   ..$ tls.record.length      : chr  "512" "512" "512" "512" ...
    ##   ..$ tls.handshake          :'data.frame':  6 obs. of  31 variables:

This structure include the `tls.handshake`, so we can wind down a twisty
path to get to our quarry:

``` r
# grab the first handshake random
proton_hands$`_source`$layers$tls$tls.record$tls.handshake$tls.handshake.random[1]
```

    ## [1] "24:e9:25:13:b9:7a:03:48:f7:33:d1:69:96:92:9a:79:be:21:b0:b1:40:0c:d7:e2:86:2a:73:2c:e7:77:5b:70"

There’s one “nit” left, which is that the challenge answer box expects a
value with no colons. We can quickly fix that:

``` r
gsub(":", "", proton_hands$`_source`$layers$tls$tls.record$tls.handshake$tls.handshake.random[1])
```

    ## [1] "24e92513b97a0348f733d16996929a79be21b0b1400cd7e2862a732ce7775b70"

## What is the server certificate public key that was used in TLS session: `da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4ff`?

### Question Setup

We learned in the previous chapter that knowledge of TLS sessions can be
pretty handy when poking at PCAPs and this chapter expands upon that
knowledge by asking us to reveal the server certificate public key that
was used in TLS session:
`da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4ff`?
Being able to extract and compare TLS session elements is another handy
skill, and this example will let us explore another set of `tshark`
display filter and output fields that can come in usful in future IRL
scenarios.

### Solving the quest with `tshark` custom filters (and a *wee* bit of R)

That’s right, we’re not going to make you generate giant JSON files and
sift through horribly nested R lists. We *are* going to need *some* help
from R since the question gave us a session byte string *without*
colons, which `tshark` requires in their filters, so we’ll use R to
generate that before passing the info to the command line.

We’ll use regular expression-based find/replace via the `{stringi}`
package. In the regex below, the `(?!$)` hieroglyphics means “but not at
the end of the string” and the `(.{2})` hieroglyphics means “match every
two characters and take them as a group”. Once we have a valid value, we
can use the `{glue}` package to add that to the `tshark` command line
call via string interpolation.

Speaking of `tshark` filters, we’re searching on
`tls.handshake.session_id` for the provided session, and if we re-visit
the [online display filter
reference](https://www.wireshark.org/docs/dfref/t/tls.html) we can see
that the “public key” (or `Pubkey`) is `tls.handshake.server_point`, so
we can focus on just extracting that.

``` r
library(stringi)
library(glue)

(stri_replace_all_regex(
  str = "da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4ff",
  pattern = "(.{2})(?!$)",
  replacement = "$1:"
) -> session_to_find)
```

    ## [1] "da:4a:00:00:34:2e:4b:73:45:9d:73:60:b4:be:a9:71:cc:30:3a:c1:8d:29:b9:90:67:e4:6d:16:cc:07:f4:ff"

``` r
system(
  glue(
    "tshark -e tls.handshake.server_point -Tfields -r maze/maze.pcapng tls.handshake.session_id == '{session_to_find}'"
  ), intern=TRUE
)
```

    ## [1] "04edcc123af7b13e90ce101a31c2f996f471a7c8f48a1b81d765085f548059a550f3f4f62ca1f0e8f74d727053074a37bceb2cbdc7ce2a8994dcd76dd6834eefc5438c3b6da929321f3a1366bd14c877cc83e5d0731b7f80a6b80916efd4a23a4d"

## What time was a non-standard folder created on the FTP server on the 20th of April?

### Question Setup

We weren’t fibbing when we said we’d be back in FTP land sooner than
later. As stated previously, FTP is a cleartext protocol so we can see
*everything* that goes on between a client and server. If someone, say,
asks for a directory listing (via the `LIST` command — ref: [RFC
959](https://www.rfc-editor.org/rfc/rfc959.html)) we’ll see whatever the
server returned, which usually contains file/directory metadata. If we
can find this response, we’ll be able to determine what time a
non-standard folder was created on the FTP server on the 20th of April.

### Solving the quest with `tshark` custom filters (and a *wee* bit of R)

Unfortunately, we do not have enough data in our Zeek `ftp.log` to
answer this question. However, `tshark` has a plethora of [FTP
filters](https://www.wireshark.org/docs/dfref/f/ftp.html) we can use.
Let’s extract all of the FTP packets that have `ftp-data` elements
(associated with the `LIST` request) since we know they’ll have the
responses:

``` r
system("tshark -T json -r maze/maze.pcapng ftp-data and ftp-data.command == 'LIST' > maze/ftp-q1.json")

ftpq1 <- fromJSON("maze/ftp-q1.json", simplifyDataFrame = FALSE)
```

Let’s see what layers we have available:

``` r
names(ftpq1[[1]]$`_source`$layers)
```

    ##  [1] "frame"                              "eth"                               
    ##  [3] "ip"                                 "tcp"                               
    ##  [5] "ftp-data"                           "ftp-data.setup-frame"              
    ##  [7] "ftp-data.setup-method"              "ftp-data.command"                  
    ##  [9] "ftp-data.command-frame"             "ftp-data.current-working-directory"
    ## [11] "data-text-lines"

Sure enough, we have `ftp-data` element in there, including the
`data-text-lines` responses which we can inspect:

``` r
ftpq1 %>% 
  map(~.x[c(1,2,4)]) %>% 
  bind_rows() %>%  # make a data frame out of the individual list elements
  glimpse() %>% 
  pull(`_source`) %>% 
  pluck("layers", "data-text-lines") %>% 
  names()
```

    ## Rows: 4
    ## Columns: 3
    ## $ `_index`  <chr> "packets-2021-04-29", "packets-2021-04-29", "packets-2021-04…
    ## $ `_type`   <chr> "doc", "doc", "doc", "doc"
    ## $ `_source` <named list> [["0", ["wlo1"], "1", "Apr 29, 2021 21:01:26.926740094 EDT",…

    ## [1] "drwxr-xr-x    2 1000     1000         4096 Feb 23 06:37 Desktop\\r\\n"  
    ## [2] "drwxr-xr-x    2 1000     1000         4096 Apr 29 16:42 Documents\\r\\n"
    ## [3] "drwxr-xr-x    2 1000     1000         4096 Feb 23 06:37 Downloads\\r\\n"
    ## [4] "drwxr-xr-x    2 1000     1000         4096 Feb 23 06:37 Music\\r\\n"    
    ## [5] "drwxr-xr-x    2 1000     1000         4096 Feb 23 06:37 Pictures\\r\\n" 
    ## [6] "drwxr-xr-x    2 1000     1000         4096 Feb 23 06:37 Public\\r\\n"   
    ## [7] "drwxr-xr-x    2 1000     1000         4096 Feb 23 06:37 Templates\\r\\n"
    ## [8] "drwxr-xr-x    2 1000     1000         4096 Feb 23 06:37 Videos\\r\\n"   
    ## [9] "dr-xr-x---    4 65534    65534        4096 Apr 20 17:53 ftp\\r\\n"

From that listing we can tell the odd `ftp` folder was created at
`17:53`

## What country is the MAC address of the FTP server registered in?

### Question Setup

We did say that MAC addresses provide quite a bit of metadata. You can
head on over to [DeepMac](http://search.deepmac.org/) if you want to
up-close-and-personal verification of that. In fact, you can use that
search page instead of the `{MACtools}` package (below) if you’re having
trouble getting `{MACtools}` installed or don’t trust R packages from
GitHub (which you really shouldn’t).

This is a fine example of using external data sources in forensic
analyses.

### Solving the quest with Zeek `conn.log`, `ftp.log`, and R

The `ftp` data frame contains information on the FTP server, so we can
use that to get the server IP, then look that up in the `conn` data
frame to get the MAC address. Once we have that, we can use
`mac_match_registry()` or just paste the value into DeepMac.

``` r
conn %>% 
  filter(
    id.resp_h == unique(ftp$id.resp_h)
  ) %>% 
  distinct(resp_l2_addr) %>% 
  glimpse() %>% 
  pull(resp_l2_addr) %>% 
  mac_match_registry() %>% 
  select(organization_address)
```

    ## Rows: 1
    ## Columns: 1
    ## $ resp_l2_addr <chr> "08:00:27:a6:1f:86"

    ## # A tibble: 1 x 1
    ##   organization_address             
    ##   <chr>                            
    ## 1 600 Suffold St Lowell MA US 01854

## What was the camera model name used to take picture `20210429_152157.jpg`?

### Question Setup

Our last quest is a doozy. Not only do we have to work with network data
from a PCAP, but we need to also extract an image
(`20210429_152157.jpg`) from it and then poke at the image metadata to
identity the camera model name (it’s like metadata inception).

According to the [FTP RFC](https://datatracker.ietf.org/doc/html/rfc959)
files are transferred via `STOR[E]` or `RETR[IEVE]`, so we’ll need to
figure out which one has that file then do some fun data extraction.
We’ll use Zeek data, a custom `tshark` filter/extraction command and R
to finally get out of this maze.

### Solving the quest with Zeek `ftp.log`, `tshark` filters, and R

Let’s first see if we’re looking for `STOR` or `RETR`:

``` r
ftp %>% 
  filter(
    command %in% c("STOR", "RETR"),
    stri_detect_fixed(arg, "20210429_152157.jpg")
  ) %>% 
  select(command, arg, mime_type)
```

    ## # A tibble: 1 x 3
    ##   command arg                                                        mime_type 
    ##   <chr>   <chr>                                                      <chr>     
    ## 1 STOR    ftp://192.168.1.20/home/kali/Documents/20210429_152157.jpg image/jpeg

It looks like we’re going to want `STOR`!

We’ll eventually use `tshark` to grab the JPG file, but to do that we
need the TCP stream (so `tshark` can follow it and save the data).

``` r
(unique(
  system("tshark -Tfields -e tcp.stream  -r maze/maze.pcapng 'ftp-data.command == \"STOR 20210429_152157.jpg\"'", intern=TRUE)
) -> stream_id)
```

    ## [1] "17"

Now we ask `tshark` to save that to a temporary file.

``` r
tf <- tempfile(fileext = ".jpg")

# -l tells tshark to flush the buffer after each line is printed (just to be safe)
# -q tells tshark to be quiet
# -z is a special feature to output components of packets or statistics on packets.
#    here we are asking tshark to follow the entire stream and then we redirect 
#    that to a file

system(
  glue(
    "tshark -lr maze/maze.pcapng -qz 'follow,tcp,raw,{stream_id}' > {tf}"
  )
)

jpg <- read_lines(tf)

substr(jpg[1:10], 1, 80)
```

    ##  [1] ""                                                                                
    ##  [2] "==================================================================="             
    ##  [3] "Follow: tcp,raw"                                                                 
    ##  [4] "Filter: tcp.stream eq 17"                                                        
    ##  [5] "Node 0: 192.168.1.26:47052"                                                      
    ##  [6] "Node 1: 192.168.1.20:34391"                                                      
    ##  [7] "ffd8ffe19c9d4578696600004d4d002a00000008000a011000020000000900000086011200030000"
    ##  [8] "0000000000000000000088888888888806e3400065140006f440004dd400053e4000726400047040"
    ##  [9] "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    ## [10] "00000000000000000000000000000000000000000000000000000000000000000000000000000000"

That file is definitely *not* a JPG *yet*. There’s some metadata up
front, a useless bit of `======…` at the end, and the binary data has
been hex-encoded. `O_o` We’ll need to clean this up a bit before it’s a
proper image, something R is ridiculously good at.

``` r
jpg[7:(length(jpg)-1)] %>% 
  stri_trim_both() %>% # just in case
  paste0(collapse = "") %>%  # mush it all together
  sf:::CPL_hex_to_raw() -> img # there are other ways but this is super fast way to go from hex to raw
```

Now we can even view the image:

``` r
magick::image_read(img[[1]])
```

<img src="README_files/figure-gfm/ch-15-07-1.png" width="4160" />

And, check out the metadata to get the camera model:

``` r
writeBin(img[[1]], tf)

exif::read_exif(tf)
```

    ##             make    model software bits_per_sample image_width image_height
    ## 1 LG Electronics LM-Q725K                        0        4160         3120
    ##   description orientation copyright           timestamp    origin_timestamp
    ## 1                       6           2021:04:29 15:21:57 2021:04:29 15:21:57
    ##   digitised_timestamp subsecond_timestamp exposure_time f_stop iso_speed
    ## 1 2021:04:29 15:21:57              673205           207    2.2        50
    ##   subject_distance exposure_bias used_flash metering focal_length
    ## 1                              0       TRUE        2        3.701
    ##   focal_length_35mm latitude longitude altitude lens_min_focal_length
    ## 1                 0        0         0        0                     0
    ##   lens_max_focal_length lens_min_f_stop lens_max_f_stop lens_make lens_model
    ## 1                     0               0               0

``` r
unlink(tf)
```

We escaped the packet maze!
