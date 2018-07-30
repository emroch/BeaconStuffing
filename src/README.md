## Beacon Stuffing Proof-of-Concept

The program included here is a basic demonstration of beacon stuffing, showing that it is possible with commodity hardware.  More advanced uses of this technique are discussed in the paper in this repository.

The program contains two basic parts, sending and receiving messages, and a command line interface (CLI).  The sending portion has been tested on Ubuntu 18.04 and the receiving on macOS 10.13.6.

### Installing Dependencies
* Python (v3.6 or higher) - [python.org](https://www.python.org/downloads/)
    ```bash
    # Ubuntu
    $ sudo apt install python3
    ```
    ```bash
    # macOS
    $ brew install python3
    ```
* Scapy - [scapy.net](https://scapy.net)
    ```bash
    $ pip install scapy
    ```

    * Scapy has some additional dependencies. Install them using the following commands:
        ```bash
        # Ubuntu
        $ sudo apt install tcpdump graphviz imagemagick python-gnuplot python-cryptography python-pyx
        $ pip install cryptography
        ```
        ```bash
        # macOS
        $ brew install --with-python libdnet
        $ brew install https://raw.githubusercontent.com/secdev/scapy/master/.travis/pylibpcap.rb
        $ sudo brew install --with-python libdnet
        $ sudo brew install https://raw.githubusercontent.com/secdev/scapy/master/.travis/pylibpcap.rb
        ```
* Wireshark - [wireshark.org](https://www.wireshark.org)
    ```bash
    # Ubuntu
    $ sudo apt install wireshark
    ```
    macOS/Windows: Download installer from Wireshark website

* Aircrack-ng - [aircrack-ng.org](https://www.aircrack-ng.org)
    ```bash
    # Ubuntu
    sudo apt install aircrack-ng
    ```
    ```bash
    # macOS
    brew install aircrack-ng
    ```

### Setup
This proof-of-concept relies on crafting Layer 2 packets.  It therefore requires access to the Network Interface Card (NIC) of the transmission device.  In a deployment scenario, this would be a router or access point, but in this case it is a laptop.  Not all NICs will work though, it must support "frame injection."  If your NIC or driver do not support frame injection, or you are using a VM, a USB wireless card is a good option.  The [Alfa AWUSO36NH](http://a.co/3mrPaZr) with Ralink rt2800usb driver were used for testing and worked very well.

1. Connect wireless interface to transmission device.  For this example, it is assumed the transmitter is connected to a Linux computer.

2. Bring up a monitor interface.  The below assumes that the original interface is named `wlan0` and the monitor interface is called `wlan0mon`
    ```bash
    # check name of interface
    iwconfig
    # stop any processes that might cause problems
    sudo airmon-ng check
    sudo airmon-ng check kill
    # bring up monitor interface
    sudo airmon-ng start wlan0
    sudo ifconfig wlan0mon up
    ```

3. Set the channel number. The channel number must match between the transmitter and receiver, or the receiver must be able to scan all channels.
    ```bash
    # set the channel
    sudo iwconfig wlan0mon channel <number>
    # verify
    iw wlan0mon info
    ```

4. Setup the receiver.  For this example, it is assumed the receiver is a MacBook (Pro) running Wireshark,
    ```bash
    # Optional: create an alias for Airport Utility
    sudo ln -s /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport /usr/local/bin/airport
    # dissociate from any connected network
    airport -z
    # set to same channel as transmitter
    airport -c<number>
    # verify
    airport -I
    ```

### Running the Demonstration
1. Open Wireshark on the receiver.  Select the appropriate interface, but don't start capturing until you are ready to send, as the capture file will grow quickly.

2. Run the program on the transmitter, specifying your message on the command line, via a text file, or through the interactive prompt.  The file `bee.txt` is provided to demonstrate how packet fragmentation is handled. Run `beaconStuffing.py -h` for syntax details.
    ```bash
    ./beaconStuffing.py send -f bee.txt
    ```

3. Save the capture and load it using the same program.
    ```bash
    ./beaconStuffing read -f capture.pcap
    ```

4. You should see the same message you specified on the transmitter printed to the console.  You may inspect the pcap file using Scapy or Wireshark to see how the data is being packaged.
