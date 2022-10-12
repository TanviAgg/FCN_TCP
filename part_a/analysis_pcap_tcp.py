import dpkt
import struct
import sys


class TCPPacket:
    def __init__(self, src_port, dest_port, src_ip, dest_ip, seq_no, ack_no, window, header_len, payload_size,
                 syn_set, ack_set, fin_set, mss, scaling_factor, timestamp):
        self.src_port = src_port
        self.dest_port = dest_port
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.seq_number = seq_no
        self.ack_number = ack_no
        self.header_len = header_len
        self.payload_size = payload_size
        self.window = window
        self.syn_flag = syn_set
        self.ack_flag = ack_set
        self.fin_flag = fin_set
        self.mss = mss
        self.scaling_factor = scaling_factor
        self.timestamp = timestamp


class MyTCPParser:
    def __init__(self):
        pass

    def get_all_packets(self, pcap_data):
        parsed_packets = []
        for ts, packet_bytes in pcap_data:
            parsed_packet = self.parse_packet_bytes(packet_bytes, ts)
            parsed_packets.append(parsed_packet)
        return parsed_packets

    def parse_packet_bytes(self, packet_bytes, timestamp) -> TCPPacket:
        """
        Parse the packet bytes manually to extract TCP header information and payload size
        :param packet_bytes: raw bytes
        :return: parsed TCP packet with all information
        """
        # first 14 bytes are frame and 20 bytes IP headers
        tcp_header_start = 34
        # 2 bytes - 0-1
        src_port = struct.unpack(">H", packet_bytes[tcp_header_start:tcp_header_start+2])[0]
        # 2 bytes - 2-3
        dest_port = struct.unpack(">H", packet_bytes[tcp_header_start+2:tcp_header_start+4])[0]
        # 4 bytes - 4 to 7
        seq_no = struct.unpack(">I", packet_bytes[tcp_header_start+4:tcp_header_start+8])[0]
        # 4 bytes - 8 to 11
        ack_no = struct.unpack(">I", packet_bytes[tcp_header_start+8:tcp_header_start+12])[0]
        # 4 bits - 12th byte (first half)
        header_len = 4 * (struct.unpack(">B", packet_bytes[tcp_header_start+12:tcp_header_start+13])[0] // 16)
        payload_size = len(packet_bytes) - (tcp_header_start + header_len)
        # 1 byte - 13
        flags = '{:08b}'.format(struct.unpack(">B", packet_bytes[tcp_header_start + 13:tcp_header_start + 14])[0])
        syn_set = flags[6] == '1'  # 7th bit in flags
        ack_set = flags[3] == '1'  # 4th bit in flags
        fin_set = flags[7] == '1'  # 8th bit in flags
        # 2 bytes - 14-15
        window = struct.unpack(">H", packet_bytes[tcp_header_start+14:tcp_header_start+16])[0]

        # 4 bytes - 26 to 29 (from IP headers)
        src_ip = '.'.join([str(i) for i in struct.unpack(">BBBB", packet_bytes[26:30])])
        # 4 bytes - 30 to 33 (from IP headers)
        dest_ip = '.'.join([str(i) for i in struct.unpack(">BBBB", packet_bytes[30:34])])

        mss = 0
        scaling_window = 0
        if not ack_set and syn_set:
            options = struct.unpack(">B", packet_bytes[tcp_header_start+30:tcp_header_start+31])[0]
            if options == 2:
                mss = struct.unpack(">H", packet_bytes[tcp_header_start+32:tcp_header_start+34])[0]
            scaling_window = 2 ** struct.unpack(">B", packet_bytes[tcp_header_start+39:tcp_header_start+40])[0]
        parsed_packet = TCPPacket(src_port, dest_port, src_ip, dest_ip, seq_no, ack_no, window,
                                  header_len, payload_size, syn_set, ack_set, fin_set, mss, scaling_window,
                                  timestamp)
        return parsed_packet


class Analyser:
    def __init__(self, sender, receiver):
        self.sender = sender
        self.receiver = receiver
        self.protocol = ""
        self.parser = MyTCPParser()
        self.parsed_packets = []

    def load_data(self, pcap_data):
        self.parsed_packets = self.parser.get_all_packets(pcap_data)

    def count_flows_initiated(self, sender=None, receiver=None):
        """
        Count the number of flows initiated from the sender to the receiver
        We can check the SYN packets sent by the sender
        (also verify by checking the SYN-ACK packets from receiver and the FIN packets from the receiver)
        :param sender: ip of the sender
        :param receiver: ip of the receiver
        :return: List of tuples with the ports of sender and receiver for each flow
        """
        if sender is None:
            sender = self.sender
        if receiver is None:
            receiver = self.receiver
        started = []
        acked = []
        closed = []
        for packet in self.parsed_packets:
            if packet.src_ip == sender and packet.dest_ip == receiver:
                if packet.syn_flag:
                    started.append((packet.src_port, packet.dest_port))
            elif packet.src_ip == receiver and packet.dest_ip == sender:
                if packet.syn_flag and packet.ack_flag:
                    acked.append((packet.dest_port, packet.src_port))
                elif packet.fin_flag:
                    closed.append((packet.dest_port, packet.src_port))
        if len(started) == len(acked):
            return started
        elif len(acked) == len(closed):
            return acked
        else:
            return closed

    def get_all_flow_packets(self, src_port, dest_port):
        flow_packets_sender = []
        flow_packets_receiver = []
        all_flow_packets = []
        for packet in self.parsed_packets:
            if packet.src_ip == self.sender and packet.dest_ip == self.receiver:
                if packet.src_port == src_port and packet.dest_port == dest_port:
                    flow_packets_sender.append(packet)
                    all_flow_packets.append(packet)
            elif packet.src_ip == self.receiver and packet.dest_ip == self.sender:
                if packet.src_port == dest_port and packet.dest_port == src_port:
                    flow_packets_receiver.append(packet)
                    all_flow_packets.append(packet)
        return flow_packets_sender, flow_packets_receiver, all_flow_packets

    def get_flow_info(self, src_port, dest_port, n=2):
        sent, received, _ = self.get_all_flow_packets(src_port, dest_port)
        transaction_info = self.get_transaction_info(sent, received, n)
        throughput = self.compute_throughput(sent)
        loss_rate = self.compute_loss(sent)
        avg_RTT = self.estimate_RTT(sent, received)
        congestion_windows = self.compute_compression_window_sizes()
        retransmission_info = self.count_retransmissions(sent, received)
        return [transaction_info, throughput, loss_rate, avg_RTT, congestion_windows, retransmission_info]

    def get_transaction_info(self, sent, received, n=2):
        """
        Extract sequence number, Ack number and receive window information from the flow
        :param n: first n transactions for which information is extracted
        :return: n*[sequence number, Ack number, receive window]
        """
        transaction_info = []
        idx = 0
        # find SYN packet
        while idx < len(sent) and not sent[idx].syn_flag:
            idx += 1
        scaling_factor_sender = sent[idx].scaling_factor
        idx += 1
        # find first ACK (this is the end of connection setup - 3 way handshake)
        while idx < len(sent) and not sent[idx].ack_flag:
            idx += 1
        idx += 1
        # find first n transactions
        for j in range(n):
            transaction = [(sent[idx + j].seq_number, sent[idx + j].ack_number,
                            sent[idx + j].window * scaling_factor_sender)]
            idx_r = 0
            while idx_r < len(received) and (not received[idx_r].syn_flag and not received[idx_r].ack_flag):
                idx_r += 1
            for packet in received[idx_r+1:]:
                if packet.seq_number == sent[idx + j].ack_number:
                    transaction.append((packet.seq_number, packet.ack_number, packet.window * scaling_factor_sender))
                    break
            transaction_info.append(transaction)
        return transaction_info

    def compute_throughput(self, packets):
        total_size = 0
        for packet in packets:
            total_size += (packet.payload_size + packet.header_len + 34)
        time_elapsed = packets[-1].timestamp - packets[0].timestamp
        return total_size/time_elapsed

    def compute_loss(self, packets):
        retransmitted = 0
        unique_sent = set([])
        for packet in packets:
            if packet.seq_number not in unique_sent:
                unique_sent.add(packet.seq_number)
            else:
                retransmitted += 1
        retransmitted -= 1  # account for the PSH/ACK packet with same number
        return retransmitted, retransmitted / len(unique_sent)

    def estimate_RTT(self, sent, received):
        sent_timestamps = {}
        received_timestamps = {}
        retransmitted_seq_numbers = set([])
        for packet in sent:
            if packet.seq_number in sent_timestamps:
                retransmitted_seq_numbers.add(packet.seq_number)
            else:
                sent_timestamps[packet.seq_number] = packet.timestamp
        for packet in received:
            received_timestamps[packet.ack_number] = packet.timestamp

        sum_RTTs = 0
        num_transactions = 0
        for seq_number, ts in sent_timestamps.items():
            if seq_number not in retransmitted_seq_numbers and seq_number in received_timestamps:
                sum_RTTs += (received_timestamps[seq_number] - ts)
                num_transactions += 1
        return sum_RTTs/num_transactions

    def compute_compression_window_sizes(self):
        return []

    def count_retransmissions(self, sent, received):
        sent_counts = {}
        received_counts = {}
        total_retransmitted = 0
        triple_duplicate_acks = 0
        for packet in sent:
            if packet.seq_number in sent_counts:
                sent_counts[packet.seq_number] += 1
            else:
                sent_counts[packet.seq_number] = 1
        for packet in received:
            if packet.ack_number in received_counts:
                received_counts[packet.ack_number] += 1
            else:
                received_counts[packet.ack_number] = 1
        for seq_no, count in sent_counts.items():
            if seq_no in received_counts:
                if received_counts[seq_no] >= 4:
                    triple_duplicate_acks += min(sent_counts[seq_no]-1, received_counts[seq_no]//4)
                total_retransmitted += max(0, sent_counts[seq_no]-1)
        total_retransmitted -= 1
        return triple_duplicate_acks, total_retransmitted-triple_duplicate_acks


if __name__ == "__main__":
    # print(sys.byteorder)
    # myTCPParser = MyTCPParser()
    f = open('assignment2.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    # for ts, buf in pcap:
    #     parsed_p = myTCPParser.parse_packet_bytes(buf)
    #     eth = dpkt.ethernet.Ethernet(buf)
    #     ip = eth.data
    #     tcp = ip.data
    #     print("ts")
    analyser = Analyser(sender='130.245.145.12', receiver='128.208.2.198')
    analyser.load_data(pcap_data=pcap)
    print('--------------------')
    flows = analyser.count_flows_initiated()
    print(flows)
    print('--------------------')
    for flow in flows:
        transactions = analyser.get_flow_info(flow[0], flow[1])
        print(transactions)
    print('--------------------')
    print('--------------------')
    print('--------------------')
    print('--------------------')
    f.close()