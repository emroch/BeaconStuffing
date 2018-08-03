#!/usr/bin/env python3

import argparse
import sys

from cryptography.fernet import Fernet
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp, rdpcap


def main():
    # set up the argument parser
    parse = argparse.ArgumentParser(usage='\n'
                                          '\t%(prog)s [--no-encrypt] send [message]\n'
                                          '\t%(prog)s [--no-encrypt] send -f messageFile\n'
                                          '\t%(prog)s [--no-encrypt] read captureFile\n'
                                          '\t%(prog)s -h | --help')
    parse.add_argument('--no-encrypt', action='store_true',
                       help='Do not attempt to encrypt/decrypt the message')
    parse.add_argument('action', choices=['send', 'read'], metavar='action',
                       help='Whether the message is to be sent or received. Must be one of "send" or "read"')
    parse.add_argument('-m', '--message',
                       help='The message to send. If no message or input file is given, '
                            'message is read from an interactive prompt')
    parse.add_argument('-f', '--file',
                       help='Input file for message (sending) or pcap (reading)')

    # process options
    args = parse.parse_args(sys.argv[1:])
    if args.no_encrypt:
        f = None
    else:
        key = get_fernet_key()
        f = Fernet(key)
    if args.action == 'send':
        if args.message is not None:
            send_message(args.message, f)
        elif args.file is not None:
            try:
                with open(args.file, 'r') as file:
                    m = file.read()
                    send_message(m, f)
            except FileNotFoundError:
                parse.error('File not found: %s' % args.file)
        else:
            m = get_message()
            send_message(m, f)
    elif args.action == 'read':
        if not args.file:
            parse.error('Please specify a pcap file when reading a message.')
        try:
            c = rdpcap(args.file)
        except FileNotFoundError:
            parse.error('File not found: %s' % args.file)
        read_message(c, f)


def get_fernet_key(key_file='fernetkey.txt'):
    """Get a key to use for Fernet encryption.

    Attempt to read Fernet key from file, or generate a new one if the file does
    not exist.  If a new key is generated, it is saved to the same file that was
    originally searched for the key (defaults to 'fernetkey.txt' in current directory).

    :return: Fernet key
    """
    try:
        with open(key_file, 'rb') as f:
            key = f.readline()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
    return key


def get_message():
    """Get message from user via interactive prompt.

    :return: The user-generated message to send.
    """
    print('Enter your message.  Multi-line messages are accepted, press ctrl-D to submit.')
    contents = []
    while True:
        try:
            line = input('>>> ')
        except EOFError:
            print()
            break
        contents.append(line)

    return '\n'.join(contents)


def send_message(message, fernet=None):
    """Send a message using one or more beacon packets.

    :param message: The message to send
    :param fernet:  The Fernet object to use for encryption (optional)
    """
    ssid = 'fakeSSID'       # SSID to broadcast - currently used as selection filter for stuffed beacons
    iface = 'wlan0mon'      # interface to broadcast on

    frames = _build_frames(ssid, message, fernet)

    if not frames == []:
        input('\nPress enter to send %d packets\n' % len(frames))

        for frame in frames:
            sendp(frame, iface=iface, inter=0.100, loop=0, verbose=False)

        print('\nSent %d packets.' % len(frames))


def read_message(capture, fernet=None):
    """Recover a message from beacon frames contained in a pcap file.

    :param capture: The pcap to search for message
    :param fernet:  The Fernet object to use for decryption (optional)
    :return:        The decoded message
    """
    ssid = 'fakeSSID'       # SSID to filter on

    message = _read_frames(capture, ssid, fernet)

    print(message)
    return message


def _build_frames(net_SSID, message='', fernet=None):
    """ Create a list of Beacon Frames containing a message.

    Beacon frames can contain many types of Information Elements (IE), one of which is for
    vendor-specified information.  This IE contains a 3 byte OUI, 1 byte vendor-specific type,
    and up to 252 bytes of information (see below).  The vendor-specific type is meant to
    provide vendors with a way to distinguish different types of data, and therefore have
    multiple formats for IEs.  The OUI is meant to provide information about the vendor so
    the client can decode the data properly using information about a vendor's format.

        1 Byte       1 byte      3 bytes    1 byte     0-252 (Length-4) bytes
    +-------------+----------++----------+----------+---------------------------+
    |  IE Tag ID  |  Length  ||  Vendor  |  Vendor  |  Data....                 |
    |    (221)    |          ||    OUI   |   Type   |                           |
    +-------------+----------++----------+----------+---------------------------+

    Since our message may not fit in the data portion of a single IE, we will use the 802.11 MAC
    header's Sequence Control field.  This is a 2 byte field that contains a Sequence ID and a
    Fragment ID.  The Sequence ID is generated for each message and the Fragment ID is incremented
    for each fragment of a single message (i.e. a message spanning multiple frames will have a common
    Sequence ID, but each Fragment ID will be different).  These fields can be used to distinguish
    separate messages, as well as reassemble fragmented messages in order and ensure completeness.

    The 2 byte Sequence Control field is composed of the Sequence ID in the upper (more significant)
    12 bits, and the Fragment ID in the lower 4 bits.  This allows a message to be fragmented into
    32 pieces before needing a new Sequence ID.  Similarly, we can send 2**12 = 4k messages before
    needing to reuse a Sequence ID, at which point the old messages will have been processed and
    forgotten.

    This leaves the OUI and Type bytes available for other uses.  We could instead use these as a
    sequence/fragment ID, which would be less conspicuous for long messages, but is beyond the scope
    of this demonstration.  Other uses could include protocol specific information for the recipient,
    such as information regarding the type of data being sent and how to handle it.  For the purpose
    of this exercise, we will leave these fields zeroed out.

    :param net_SSID: The SSID of the fake network to broadcast
    :param message:  The data to be hidden in the beacon
    :param fernet:   A Fernet encryption object for encrypting the message, or None for no encryption
    :return:         A list of beacon frames containing slices of the message 252 bytes long
    """

    if not message:
        return []

    frame_list = []  # list of beacon frames containing the message

    # encrypt the message using the symmetric key encapsulated in Fernet object,
    # or if no encryption is desired, simply encode the message as bytes.
    if fernet is not None:
        token = fernet.encrypt(str.encode(message))
    else:
        token = str.encode(message)

    # construct the base frame layers, common to each frame
    dot11 = Dot11(type='Management', subtype=8,     # This is a beacon frame
                  addr1='ff:ff:ff:ff:ff:ff',        # ...Receiver address = broadcast
                  addr2='22:22:22:22:22:22',        # ...Transmitter address = arbitrary
                  addr3='33:33:33:33:33:33')        # ...BSSID = arbitrary
    beacon = Dot11Beacon(cap='ESS')
    essid = Dot11Elt(ID='SSID', info=net_SSID, len=len(net_SSID))
    base_frame = RadioTap() / dot11 / beacon / essid

    # Divide the token into chunks of 251 bytes.  If the token requires more than
    # one chunk, present the user with an opportunity to cancel as fragmented frames
    # can be suspicious in a network analysis tool.  Messages may not be split among
    # more than 16 frames, as the fragment ID field is only 4 bits.
    n = 251
    chunks = [token[i:i + n] for i in range(0, len(token), n)]

    if len(chunks) > 16:
        return ValueError('Message is too long.')
    elif len(chunks) > 1:
        print('Your messages is too long for a single frame and will be fragmented.')
        print('This may increase conspicuity. Press <enter> to continue, or <ctrl-D> to cancel.')
        try:
            input()
        except EOFError:
            print('Message cancelled')
            sys.exit(0)

    frag_ctr = 0x0  # 4 bit fragment ID
    seq_id = 0x000  # 12 bit sequence ID
    for i in range(len(chunks)):
        data = b'\x00\x00\x00'  # dummy OUI
        data += b'\x00'         # dummy type
        data += chunks[i]       # data

        # Add the data to a new IE and attach it to the base_frame
        payload = Dot11Elt(ID='vendor', info=data, len=len(data))
        frame = base_frame / payload

        # Set the Sequence Control field and increment fragment counter
        # Note: the SC field is a single 2 byte value, so we must combine
        # the sequence/fragment IDs to make a single value.
        value = seq_id << 4 | (frag_ctr & 0x0f)
        frame.setfieldval('SC', value)
        frag_ctr += 1

        # Set the More Frames flag on each frame except the last one
        if i < len(chunks) - 1:
            frame.setfieldval('FCfield', 'MF')

        frame_list.append(frame)

    return frame_list


def _read_frames(frame_list, net_SSID, fernet=None):
    """Process a list of captured frames to recover a message.

    To recover a message from captured packets, we will apply filters to ignore extraneous data (non-beacon
    frames or beacons for other networks).  We then reassemble the data from the remaining packets to
    get the original message (or encrypted token).

    In order to be able to recover messages longer than a single frame, we embed a Fragment ID in each frame
    of the message which identifies the order in which the frames should be reassembled.  This will usually
    be a non-issue as packets will be sent with enough time in between that they should be received in order.
    However, the Fragment ID can be useful in determining if any packets were lost in transmission, and need
    to be retransmitted.

    The MAC header also contains space for a Sequence ID, which is a unique number assigned to each different
    message.  This can be used to request retransmission of a particular message and to separate consecutive
    messages that may otherwise be jumbled.  The Sequence ID is currently ignored while reading packets.

    :param frame_list: A PacketList of captured packets, including those containing the message
    :param net_SSID:   The SSID of our fake network
    :param fernet:     A Fernet encryption object for decrypting the message, or None for no decryption
    :return:           A string containing the decrypted message, or raw token assembled from the packet list
    """

    ssid = str.encode(net_SSID)
    beacons = frame_list.filter(lambda x:'Dot11Beacon' in x)                # filter out just the beacon frames
    pkts = beacons.filter(lambda x:x.getlayer(Dot11Elt, ID=0, info=ssid))   # filter out beacons with our SSID

    data_fragments = {}  # dictionary mapping frag_ID to data contents

    # Read each of the packets matching the above criteria and save the data from the
    # Vendor IE to the dictionary.  The dictionary maps the fragment ID to the data,
    # allowing us to verify all fragments are present, and to reorder them, if necessary.
    for packet in pkts:
        frag_ID = packet.getfieldval('SC') & 0x0f
        data_layer = packet.getlayer(Dot11Elt, ID=221)
        data = data_layer.fields['info']

        if frag_ID in data_fragments:
            print('Duplicate data fragment %d' % frag_ID)
        else:
            # TODO: OUI and Type are currently unused, and must be trimmed from the data
            data_fragments[frag_ID] = data[4:]

        # Check the More Fragments bit (bit 2) of the MAC header's flags.
        # If the flag is 0, the message is done and we can break.
        # TODO: support multiple messages being sent at once by checking Sequence ID
        if not packet.getfieldval('FCfield') & 0x04:
            break

    # Reassemble the token by concatenating data fields and
    # present a warning if the fragments are not sequential.
    token = b''
    curr_ID = 0
    for ID, data in sorted(data_fragments.items()):
        if not curr_ID == ID:
            print('Missing fragment %d')
        token += data
        curr_ID += 1

    # Optionally decrypt the token and return the
    # message after decoding the byte string.
    if fernet is not None:
        return bytes.decode(fernet.decrypt(token))
    else:
        return bytes.decode(token)


if __name__ == '__main__':
    main()
