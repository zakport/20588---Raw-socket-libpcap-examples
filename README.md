# 20588---Raw-socket-libpcap-examples
Repository for examples for presentation for libpcap and raw socket usage
To launch using vscode debugger first make gdbsudo executable.


Run all examples from workspace root direcory
Raw socket examples
    Sniff raw: Show sniffer capture of ICMP packets​
        sudo ./sniff_raw | grep -B 8 icmp​
        ping 192.168.50.58​
    Inject layer 2: Injection of packet with application generated eth + IP header​
        sudo ./sniff_raw |grep -B 1 -A8 FA-CE​
        sudo ./inject_layer_2​
    Inject layer 3:  Injection of packet with application generated IP header​
        sudo ./sniff_raw |grep -B 6 -A2 1.2.3.4​
        sudo ./inject_layer_3​
Libpcap examples
Setup:
    Required programs: arpsend, ping, iperf3​
    These are all used for packet generation and sending to show different use cases of libpcap
        Ubuntu installation:
            sudo apt install iperf3 vzctl iputils-ping​
    Examples are run with a quiet network interface and with a target.
    My case I used a docker container running iperf3 --server
        Install docker
            run docker container run -it ubuntu:latest bash
            inside container run
                to find ip
                    cat /etc/hosts
                apt update
                apt install iperf3
                iperf3 --server
    Capture arp and icmp packets​
        sudo ./bin/capture 100 docker0 &
        sudo arpsend -D -e 172.17.0.2 docker0 &
        ping 172.17.0.2 -i 0.01 -c 49
        ./bin/analyse
    Capture large traffic​
        sudo ./bin/capture 1000 docker0 &
        iperf3 --client 172.17.0.2 --time 1
        ./bin/analyse


    Filter tcp and icmp packets​
        sudo ./bin/filter docker0 "tcp or icmp"
        ping 172.17.0.2 -i 0.01 -c 200 &
        iperf3 --client 172.17.0.2 --time 3
    Capture only icmp packets​
        sudo ./bin/filter docker0 icmp 
        ping 172.17.0.2 -i 0.01 -c 200 &
        iperf3 --client 172.17.0.2 --time 3


   