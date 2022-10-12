import math
import dpkt
import struct
import sys


def print_http_info(flows, info):
    n_flows = len(flows)
    with open('part_c_output.txt', 'w') as f:
        for flow_num in range(n_flows):
            f.write("HTTP information for connection {} from source port {} to destination port {}\n".format(
                flow_num+1, flows[flow_num][0], flows[flow_num][1]))
            num_req = len(info[flow_num][1][0])
            f.write("Number of HTTP requests: {}\n".format(num_req))
            for req in range(num_req):
                f.write("Request {}:\n{}\n".format(req+1, str(info[flow_num][1][0][req].payload)))
                f.write("\nResponse TCP segments: \nsrc_port\tdest_port\tseq_number\tack_number\n")
                for resp_packet in info[flow_num][1][1][req]:
                    f.write("{}\t{}\t{}\t{}".format(resp_packet[0], resp_packet[1], resp_packet[2], resp_packet[3]))
                    f.write("\n")
            f.write("\n\n")
        f.write("\n\n")


class TCPPacket:
    def __init__(self, src_port, dest_port, src_ip, dest_ip, seq_no, ack_no, window, header_len, payload,
                 payload_size, syn_set, ack_set, fin_set, mss, scaling_factor, timestamp):
        self.src_port = src_port
        self.dest_port = dest_port
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.seq_number = seq_no
        self.ack_number = ack_no
        self.header_len = header_len
        self.payload = payload
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
        # payload in TCP packet
        payload = packet_bytes[tcp_header_start+header_len:]
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
                                  header_len, payload, payload_size, syn_set, ack_set, fin_set, mss,
                                  scaling_window, timestamp)
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

    def get_flow_http_info(self, src_port, dest_port):
        sent, received, all = self.get_all_flow_packets(src_port, dest_port)
        reordered_packets = self.reorder_http_packets(sent, received)
        return 0, reordered_packets

    def compute_statistics(self):
        total_size = 0
        total_packets = len(self.parsed_packets)
        time_taken = self.parsed_packets[-1].timestamp - self.parsed_packets[0].timestamp

        for packet in self.parsed_packets:
            total_size += packet.payload_size + 34 + packet.header_len
        print("Time taken to load = {}s".format(round(time_taken, 5)))
        print("Total packets transferred = {}".format(total_packets))
        print("Total size of data transferred = {}".format(total_size))
        return [total_size, total_packets, time_taken]

    def reorder_http_packets(self, sent, received):
        """
        We can find the request/response pairs based on the following logic:
        1. request will be sent from sender - Seq x, Ack y
        2. response will be sent by the receiver - Seq y, Ack x+1
        So, a matching pair will be one where request ACK number matches response SEQ number.
        :param sent: packets sent from sender
        :param received: packets sent from receiver
        :return:
        """
        received_packets = {}
        requests = []
        for packet in sent:
            if str(packet.payload).find('GET') != -1:
                requests.append(packet)
        for packet in received:
            # if str(packet.payload).find('HTTP') != -1:
            received_packets[packet.seq_number] = packet

        responses = []
        for request_packet in requests:
            response = []
            response_seq_no = request_packet.ack_number
            while response_seq_no in received_packets:
                response_packet = received_packets[response_seq_no]
                if response_packet.fin_flag:
                    break
                response.append((response_packet.src_port, response_packet.dest_port,
                                  response_packet.seq_number, response_packet.ack_number))
                if response_packet.payload_size == 0:
                    break
                response_seq_no += response_packet.payload_size
            responses.append(response)

        return requests, responses


if __name__ == "__main__":
    # print(sys.byteorder)
    print('====================')
    print('Analysis of http_1080.pcap')
    f = open('http_1080.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    analyser = Analyser(sender='192.168.0.61', receiver='34.193.77.105')
    analyser.load_data(pcap_data=pcap)
    print('--------------------')
    flows = analyser.count_flows_initiated()
    print('Number of flows initiated = ', len(flows))
    print('--------------------')
    all_flow_info = []
    for i in range(len(flows)):
        info = analyser.get_flow_http_info(flows[i][0], flows[i][1])
        all_flow_info.append(info)
    print_http_info(flows, all_flow_info)
    print('Reconstructed HTTP request/response from http_1080.pcap into part_c_output.txt. Check the file for details.')
    print('====================')

    print('Comparison of the three cases')
    print('Statistics for http_1080.pcap')
    print('--------------------')
    print('Number of flows initiated = ', len(flows))
    analyser.compute_statistics()

    print('Statistics for http_1081.pcap')
    print('--------------------')
    f = open('http_1081.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    analyser = Analyser(sender='192.168.0.61', receiver='34.193.77.105')
    analyser.load_data(pcap_data=pcap)
    flows = analyser.count_flows_initiated()
    print('Number of flows initiated = ', len(flows))
    analyser.compute_statistics()
    print('--------------------')

    print('Statistics for http_1082.pcap')
    print('--------------------')
    f = open('http_1082.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    analyser = Analyser(sender='192.168.0.61', receiver='34.193.77.105')
    analyser.load_data(pcap_data=pcap)
    flows = analyser.count_flows_initiated()
    print('Number of flows initiated = ', len(flows))
    analyser.compute_statistics()
    print('--------------------')
    print('====================')
