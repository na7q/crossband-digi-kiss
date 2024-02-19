import socket
import threading
from datetime import datetime
import signal
import sys
import time
import aprslib
import errno
import json
from datetime import datetime, timedelta
import ctypes

#------------------ Start of user configuration --------------------#

#HF Port
vara_ip = "192.168.0.1"
vara_port = 8200

#VHF Port
tnc_ip = "192.168.0.2"
tnc_port = 8001

#Digi callsign for HF and VHF. Add seperate call feature for HF and VHF in future version
digi_call = 'NA7Q-1'

#Digi only directly heard stations. Ignored by Regen
direct_path_vhf = False
direct_path_hf = True

#Regen UNFILTERED HF Traffic to VHF. Does NOT bypass dupe_time_vara. Ignores all other settings.
hf_regen = True
#Regen FILTERED VHF Traffic to HF. Does NOT bypass dupe_time_tnc. Ignores all other settings.
vhf_regen = True

#Flags to control data forwarding
forward_vara_to_tnc_enabled = True
forward_tnc_to_vara_enabled = True

#Dupe time prevents duplicate packets from VARA or TNC from being forwarded during that time
dupe_time_tnc = 90
dupe_time_vara = 90

#Call Filter for VHF to HF Traffic. True or False. USE WITH CAUTION if set to FALSE!!
allowed_callsign_filter = True

#Only these callsigns are allowed to pass from TNC to VARA. Must specify call and ssid.
allowed_callsign = {"KI7EOR-7", "NA7Q-7", "NA7Q-3", "NA7Q-4"}

#Paths are set by alias without ssid. Will digi anything higher than itself. i.e. WIDE2-5 or WIDE1-3.
digi_paths = ['PNW1', 'PNW2', 'WIDE1', 'WIDE2']

#------------------ End of user configuration --------------------#

#Disable Quick Edit for Windows. Prevents command prompt from stalling the program.
kernel32 = ctypes.windll.kernel32
kernel32.SetConsoleMode(kernel32.GetStdHandle(-10), 128) 

#Attempt to suppress unusual duplicate packets from KISS sockets (mainly VARA)
last_processed_timestamp = None

# Global dictionary to keep track of received packets and their timestamps
received_packets_vara = {}
received_packets_tnc = {}

#KISS FEND FESC
KISS_FEND = 0xC0
KISS_FESC = 0xDB
KISS_TFEND = 0xDC
KISS_TFESC = 0xDD

#Global VARA and TNC Socket Variables
vara_socket = None
tnc_socket = None

#Sockets are ready or not
vara_socket_ready = False
tnc_socket_ready = False

#Encode KISS Call SSID Destination 
def encode_address(address, final):
    try:
        digi = False

        if "-" not in address:
            address = address + "-0"  # default to SSID 0
        if "*" in address:
            digi = True
            address = address.replace('*', '')

        call, ssid = address.split('-')
        
        if len(call) < 6:
            call = call + " " * (6 - len(call))  # pad with spaces
        
        encoded_call = [ord(x) << 1 for x in call[0:6]]
        encoded_ssid = (int(ssid) << 1) | 0b01100000 | (0b00000001 if final else 0)

        # Include the 7th bit in the SSID byte based on the 'digi' flag
        if digi:
            encoded_ssid |= 0x80

        return encoded_call + [encoded_ssid]
    
    except ValueError as e:
        print("Error encoding address:", e)

# Encode KISS Frame
def encode_ui_frame(source, destination, message, *paths):
    src_addr_final = not paths or (len(paths) == 1 and paths[0] == '')  # src_addr_final is True if no paths are provided
    src_addr = encode_address(source.upper(), src_addr_final)
    dest_addr = encode_address(destination.upper(), False)

    # Ensure paths is a list of strings
    if isinstance(paths, (tuple, list)) and len(paths) == 1 and isinstance(paths[0], str):
        paths = paths[0].split(',')
    elif not all(isinstance(path, str) for path in paths):
        print("Invalid paths format. Returning None.")
        return None

    encoded_paths = [] if not paths or paths[0] == '' else [encode_address(path.upper(), final) for final, path in zip([False] * (len(paths) - 1) + [True], paths)]

    c_byte = [0x03]
    pid = [0xF0]
    msg = [ord(c) for c in message]

    packet = dest_addr + src_addr + sum(encoded_paths, []) + c_byte + pid + msg

    packet_escaped = []
    for x in packet:
        if x == KISS_FEND:
            packet_escaped.append(KISS_FESC)
            packet_escaped.append(KISS_TFEND)
        elif x == KISS_FESC:
            packet_escaped.append(KISS_FESC)
            packet_escaped.append(KISS_TFESC)
        else:
            packet_escaped.append(x)

    kiss_cmd = 0x00
    kiss_frame = [KISS_FEND, kiss_cmd] + packet_escaped + [KISS_FEND]

    kiss_frame = bytes(kiss_frame)
    
    #print_hex_and_binary(kiss_frame, "Encoded Data: ")    
    
    return kiss_frame

def decode_address(encoded_data):
    call = "".join([chr(byte >> 1) for byte in encoded_data[:6]]).rstrip()
    ssid = (encoded_data[6] >> 1) & 0b00001111
    
    if ssid == 0:
        address = call
    else:
        address = f"{call}-{ssid}"

    return address

def print_hex_and_binary(data, prefix=""):
    hex_data = ' '.join([f"{hex(b)[2:].zfill(2)}" for b in data])
    binary_data = ' '.join([f"{format(b, '08b')}" for b in data])
    decimal_data = ' '.join([f"{b}" for b in data])
    print(f"{prefix}Hex: {hex_data}")
    print(f"{prefix}Binary: {binary_data}")
    print(f"{prefix}Decimal: {decimal_data}")


def decode_kiss_frame(kiss_frame, formatted_time):

    #print_hex_and_binary(kiss_frame, "Decoded Data: ")


    decoded_packet = []
    is_escaping = False

    for byte in kiss_frame:
        if is_escaping:
            if byte == KISS_TFEND:
                decoded_packet.append(KISS_FEND)
            elif byte == KISS_TFESC:
                decoded_packet.append(KISS_FESC)
            else:
                # Invalid escape sequence, ignore or handle as needed
                pass
            is_escaping = False
        else:
            if byte == KISS_FEND:
                if 0x03 in decoded_packet:
                    c_index = decoded_packet.index(0x03)
                    if c_index + 1 < len(decoded_packet):
                        pid = decoded_packet[c_index + 1]
                        ax25_data = bytes(decoded_packet[c_index + 2:])

                        if ax25_data and ax25_data[-1] == 0x0A:
                            ax25_data = ax25_data[:-1] + bytes([0x0D])

                        dest_addr_encoded = decoded_packet[1:8]
                        src_addr_encoded = decoded_packet[8:15]
                        src_addr = decode_address(src_addr_encoded)
                        dest_addr = decode_address(dest_addr_encoded)

                        paths_start = 15
                        paths_end = decoded_packet.index(0x03)
                        paths = decoded_packet[paths_start:paths_end]

                        if paths:
                            path_addresses = []
                            path_addresses_with_asterisk = []
                            for i in range(0, len(paths), 7):
                                path_chunk = paths[i:i+7]
                                path_address = decode_address(path_chunk)


                                digi = False  # Initialize digi to False

                                # 7th byte carries SSID or digi:
                                seven_chunk = path_chunk[6] & 0xFF
                                                        
                                #print(f"Path (Hex): {' '.join([hex(b)[2:].zfill(2) for b in path_chunk])}")

                                                        
                                if seven_chunk & 0x80:
                                    digi = True

                                #print(digi)

                                # Check if digi is True, then append '*' to the path_address_with_asterisk
                                if digi:
                                    path_address_with_asterisk = f"{path_address}*"
                                else:
                                    path_address_with_asterisk = path_address

                        
                                path_addresses.append(path_address)
                                path_addresses_with_asterisk.append(path_address_with_asterisk)

                            path_addresses_str = ','.join(path_addresses_with_asterisk)
                        else:
                            path_addresses_str = ""

                        if path_addresses_str:
                            packet = f"{src_addr}>{dest_addr},{path_addresses_str}:{ax25_data.decode('ascii', errors='ignore')}"
                        else:
                            packet = f"{src_addr}>{dest_addr}:{ax25_data.decode('ascii', errors='ignore')}"

                        print(f"{formatted_time}: {packet}")
    
                        return packet

            elif byte == KISS_FESC:
                is_escaping = True
            else:
                decoded_packet.append(byte)

def connect_tnc_socket():
    global tnc_socket, tnc_socket_ready

    while True:
        try:
            # Initialize the socket and connect to the TNC
            tnc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tnc_socket.connect((tnc_ip, tnc_port))
            print("Connected to TNC")
            tnc_socket_ready = True  # Set the flag to indicate that the socket is ready

            # If the connection was successful, break out of the loop
            break

        except socket.error as e:
            if e.errno == errno.ECONNREFUSED:
                print("Connection to TNC refused. Retrying in 10 seconds...")
            else:
                print("Socket error:", str(e))
                tnc_socket_ready = False
                time.sleep(1)  # Wait for a while before attempting to reconnect

        except Exception as e:
            print("Error connecting to TNC: {}".format(e))
            tnc_socket_ready = False
            time.sleep(1)  # Wait for a while before attempting to reconnect

        time.sleep(10)  # Wait for 10 seconds before retrying

    return tnc_socket


def connect_vara_socket():
    global vara_socket, vara_socket_ready

    while True:
        try:
            # Initialize the socket and connect to the TNC
            vara_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            vara_socket.connect((vara_ip, vara_port))
            print("Connected to VARA")
            vara_socket_ready = True  # Set the flag to indicate that the socket is ready

            # If the connection was successful, break out of the loop
            break

        except socket.error as e:
            if e.errno == errno.ECONNREFUSED:
                print("Connection to VARA refused. Retrying in 10 seconds...")
            else:
                print("Socket error:", str(e))
                vara_socket_ready = False
                time.sleep(1)  # Wait for a while before attempting to reconnect

        except Exception as e:
            print("Error connecting to VARA: {}".format(e))
            vara_socket_ready = False
            time.sleep(1)  # Wait for a while before attempting to reconnect

        time.sleep(10)  # Wait for 10 seconds before retrying

    return vara_socket

def aprslib_parse_vara_to_tnc(line, data):
    global received_packets_vara
    
    try:
        payload = line.split(':', 1)[-1].strip()

        aprs_packet = aprslib.parse(line.strip())
        #print(aprslib.parse(line.strip()))

        if aprs_packet:
            print("Packet is valid!")
            callsign = aprs_packet.get('from', None)
            addresse = aprs_packet.get('addresse', None)
            to = aprs_packet.get('to', None)
            path = aprs_packet.get('path', None)
            #thirdparty = aprs_packet.get('thirdparty', None)
            
            formatted_path = ' '.join(path)

            if callsign and to and payload:
                # Check if the same packet was received within the last 60 seconds
                if formatted_path:
                    key = (callsign, to, tuple(formatted_path.split()), payload)
                else:
                    # If formatted_path is empty, use a placeholder value for it
                    key = (callsign, to, ('',), payload)  # Using an empty string as a placeholder
                print("key", key)
                
                current_time = datetime.now()

                if key in received_packets_vara:
                    last_received_time = received_packets_vara[key]
                    time_difference = current_time - last_received_time

                    if time_difference.total_seconds() <= dupe_time_vara: #Adjust for newly digipeated calls??
                        print(f"Duplicate packet received within the last {dupe_time_vara} seconds.")
                        return None

            # Update the timestamp for the received packet
            received_packets_vara[key] = current_time

            formatted_time = datetime.now().strftime("%H:%M:%S")

            #Regen
            if hf_regen and forward_vara_to_tnc_enabled:
                tnc_socket.sendall(data)
                print("Regen Data Sent to TNC")
                return None

            # Check if callsign is equal to digi_call
            if callsign == digi_call:
                print(f"{callsign} is equal to {digi_call}. Returning None.")
                return None

            # Extract and format the path without brackets and quotes
            formatted_path = ' '.join(path)
            new_path = digipeating_to_vhf(*formatted_path.split())

            # Check if new_path is None, break out of the function
            if new_path is None:
                return

            formatted_path = new_path
                
            encoded_packet = encode_ui_frame(callsign, to, payload, *formatted_path.split())

            decoded_packet = decode_kiss_frame(encoded_packet, formatted_time)

            if forward_vara_to_tnc_enabled:
                # Forward data to the destination socket
                tnc_socket.sendall(encoded_packet)
                print("Forwarding data to TNC.")
            else:
                print("Data forwarding is disabled.")

    except Exception as e:
        # Handle the exception (or ignore it, if no handling is needed)
        print("Error while parsing APRS packet from VARA:", e)

          

def aprslib_parse_tnc_to_vara(line, data):
    global received_packets_tnc

    try:
        payload = line.split(':', 1)[-1].strip()


        aprs_packet = aprslib.parse(line.strip())
        #print(aprslib.parse(line.strip()))

        # Check if the packet's path doesn't contain '*'
        if aprs_packet:
            callsign = aprs_packet.get('from', None)
            addresse = aprs_packet.get('addresse', None)
            to = aprs_packet.get('to', None)
            path = aprs_packet.get('path', None)
            #List of paths
            formatted_path = ' '.join(path)

            if callsign and to and payload:
                # Check if the same packet was received within the last 60 seconds using the Callsign, tocall, and payload data.
                key = (callsign, to, payload)
                current_time = datetime.now()

                if key in received_packets_tnc:
                    last_received_time = received_packets_tnc[key]
                    time_difference = current_time - last_received_time

                    if time_difference.total_seconds() <= dupe_time_tnc:
                        print(f"Duplicate packet received within the last {dupe_time_tnc} seconds.")
                        return None

            # Update the timestamp for the received packet
            received_packets_tnc[key] = current_time

            formatted_time = datetime.now().strftime("%H:%M:%S")

            #Regen
            if vhf_regen and forward_tnc_to_vara_enabled and callsign in allowed_callsign or allowed_callsign_filter is False:
                print("Callsign found in list.")
                vara_socket.sendall(data)
                print("Regen Data Sent to VARA\n")
                return None

            # Check if callsign is equal to digi_call
            if callsign == digi_call:
                print(f"{callsign} is equal to {digi_call}. Returning None.")
                return None
                
            # Extract and format the path without brackets and quotes
            new_path = digipeating_to_hf(*formatted_path.split())

            # Check if new_path is None, break out of the function
            if new_path is None:
                return

            formatted_path = new_path
                
            encoded_packet = encode_ui_frame(callsign, to, payload, *formatted_path.split())

            #digipeated packet
            decoded_packet = decode_kiss_frame(encoded_packet, formatted_time)

            # Check if "from" is in the allowed callsigns for TNC
            if callsign in allowed_callsign or allowed_callsign_filter is False:
                print("Callsign found in list.")
                
                if forward_tnc_to_vara_enabled:
                    # Forward data to the destination socket
                    vara_socket.sendall(encoded_packet)
                    print("Forwarding data to VARA.")
                else:
                    print("Data forwarding is disabled.")
            else:
                print("Callsign not in allowed list. Not forwarding.")

    except Exception as e:
        # Handle the exception (or ignore it, if no handling is needed)
        print("Error while parsing APRS packet from TNC:", e)


def digipeating_to_vhf(*paths):
    global direct_path_hf

    modified_paths = []
    found_matching_path = False
    digi_path = None

    # Check if all paths are initially marked with '*'
    all_paths_marked = all('*' in path for path in paths)

    for path in paths:

        if '*' in path:
            if direct_path_hf:
                print("Direct Only Digipeating Enabled.")
                return None
            else:
                # If the path contains '*', it is considered used, keep it as is. And process next path.
                modified_paths.append(path)
        
        elif digi_call in path: #Add feature, if no * then digi.
            # If digi_call is found in paths, return None
            print(f"{digi_call} found in paths. Returning None.")
            return None
            
        elif not found_matching_path and any(path.startswith(digi_path + '-') for digi_path in digi_paths):
            # If it's the first matching path, replace it
            found_matching_path = True
            digi_path_ssid = path.split('-')
            ssid_number = int(digi_path_ssid[1]) - 1

            if ssid_number == 0:
                # If the SSID is 0, replace with digi_call + '*'
                modified_paths.append(f"{digi_call}*")
            else:
                # Decrement the SSID and add both paths
                decremented_path = f"{digi_path_ssid[0]}-{ssid_number}"
                modified_paths.extend([f"{digi_call}*", decremented_path])
                print(f"Decrementing path, creating new path: {decremented_path}")
        elif not found_matching_path:
            # If the first unused path doesn't match, return None
            print(f"First unused path doesn't match. Returning None.")
            return None
        else:
            # If the path doesn't match the conditions, keep it as is
            print(f"Path doesn't match conditions, keeping it as is: {path}")
            modified_paths.append(path)

    # If all paths are used when received, return None
    if all_paths_marked and all('*' in path for path in modified_paths):
        print("All paths are used when received. Returning None.")
        return None

    result = ' '.join(modified_paths)
    return result


def digipeating_to_hf(*paths):
    global direct_path_vhf

    modified_paths = []
    found_matching_path = False
    digi_path = None

    # Check if all paths are initially marked with '*'
    all_paths_marked = all('*' in path for path in paths)

    for path in paths:

        if '*' in path:
            if direct_path_vhf:
                print("Direct Only Digipeating Enabled")
                return None
            else:
                # If the path contains '*', it is considered used, keep it as is
                modified_paths.append(path)
        
        elif digi_call in path: #Add feature, if no * then digi.
            # If digi_call is found in paths, return None
            print(f"{digi_call} found in paths. Returning None.")
            return None
            
        elif not found_matching_path and any(path.startswith(digi_path + '-') for digi_path in digi_paths):
            # If it's the first matching path, replace it
            found_matching_path = True
            digi_path_ssid = path.split('-')
            ssid_number = int(digi_path_ssid[1]) - 1

            if ssid_number == 0:
                # If the SSID is 0, replace with digi_call + '*'
                modified_paths.append(f"{digi_call}*")
            else:
                # Decrement the SSID and add both paths
                decremented_path = f"{digi_path_ssid[0]}-{ssid_number}"
                modified_paths.extend([f"{digi_call}*", decremented_path])
                print(f"Decrementing path, creating new path: {decremented_path}")
        elif not found_matching_path:
            # If the first unused path doesn't match, return None
            print(f"First unused path doesn't match. Returning None.")
            return None
        else:
            # If the path doesn't match the conditions, keep it as is
            print(f"Path doesn't match conditions, keeping it as is: {path}")
            modified_paths.append(path)

    # If all paths are used when received, return None
    if all_paths_marked and all('*' in path for path in modified_paths):
        print("All paths are used when received. Returning None.")
        return None

    result = ' '.join(modified_paths)
    return result

def tnc_data(socket):
    global tnc_socket_ready, last_processed_timestamp

    frame_buffer = []
    last_data = None
    last_data_timestamp = None

    while True:
        try:
            data = socket.recv(1024)
            if not data:
                print("Connection to TNC terminated. Reestablishing connection in 5 seconds...")
                time.sleep(5)  # Wait for 5 seconds before attempting to reconnect
                socket = connect_tnc_socket()  # Reestablish the connection
                print("Reconnected to TNC.")
                frame_buffer = []  # Reset the frame_buffer after reconnecting
                tnc_socket_ready = True  # Set the flag to indicate that the socket is ready

            frame_buffer.extend(data)

            if KISS_FEND in frame_buffer:
                hex_data = ' '.join([hex(b)[2:].zfill(2) for b in frame_buffer])
                formatted_time = datetime.now().strftime("%H:%M:%S")

                print("\nReceived TNC Data")
                raw_packet = decode_kiss_frame(frame_buffer, formatted_time)

                # Check if the current packet has the same timestamp as the last processed packet
                current_timestamp = time.time()
                if raw_packet and current_timestamp != last_processed_timestamp:
                    last_processed_timestamp = current_timestamp                 
                    # Run aprslib_parse_tnc_to_vara in a separate thread
                    aprs_thread = threading.Thread(target=aprslib_parse_tnc_to_vara, args=(raw_packet, data))
                    aprs_thread.start()
                    
            frame_buffer = []

        except ConnectionResetError as e:
            print("Connection reset by remote host:", str(e))
            tnc_socket_ready = False  # Reset the socket_ready flag to indicate a disconnected state
            time.sleep(1)  # Wait for a while before attempting to reconnect
            socket = connect_tnc_socket()  # Reestablish the connection
            tnc_socket_ready = True  # Set the flag to indicate that the socket is ready

        except IndexError as e:
            frame_buffer = []  # Reset the frame_buffer to handle the IndexError
            continue  # Skip the rest of the loop and start from the beginning

        except Exception as e:
            print("Error in tnc_data:", str(e))
            tnc_socket_ready = False  # Reset the socket_ready flag to indicate a disconnected state
            time.sleep(1)  # Wait for a while before attempting to reconnect
            socket = connect_tnc_socket()  # Reestablish the connection
            tnc_socket_ready = True  # Set the flag to indicate that the socket is ready

def vara_data(socket):
    global vara_socket_ready, last_processed_timestamp

    frame_buffer = []
    last_data = None
    last_data_timestamp = None

    while True:
        try:
            data = socket.recv(1024)
            if not data:
                print("Connection to VARA terminated. Reestablishing connection in 5 seconds...")
                time.sleep(5)  # Wait for 5 seconds before attempting to reconnect
                socket = connect_vara_socket()  # Reestablish the connection
                print("Reconnected to VARA.")
                frame_buffer = []  # Reset the frame_buffer after reconnecting
                tnc_socket_ready = True  # Set the flag to indicate that the socket is ready
                
            frame_buffer.extend(data)

            if KISS_FEND in frame_buffer:
                hex_data = ' '.join([hex(b)[2:].zfill(2) for b in frame_buffer])
                formatted_time = datetime.now().strftime("%H:%M:%S")

                print("\nReceived VARA Data")
                raw_packet = decode_kiss_frame(frame_buffer, formatted_time)
                
                # Check if the current packet has the same timestamp as the last processed packet
                current_timestamp = time.time()
                if raw_packet and current_timestamp != last_processed_timestamp:
                    last_processed_timestamp = current_timestamp                 
                    # Run aprslib_parse_tnc_to_vara in a separate thread
                    aprs_thread = threading.Thread(target=aprslib_parse_vara_to_tnc, args=(raw_packet, data))
                    aprs_thread.start()
                    
                frame_buffer = []
               
        except ConnectionResetError as e:
            print("Connection reset by remote host:", str(e))
            vara_socket_ready = False  # Reset the socket_ready flag to indicate a disconnected state
            time.sleep(1)  # Wait for a while before attempting to reconnect
            socket = connect_vara_socket()  # Reestablish the connection
            vara_socket_ready = True  # Set the flag to indicate that the socket is ready

        except IndexError as e:
            frame_buffer = []  # Reset the frame_buffer to handle the IndexError
            continue  # Skip the rest of the loop and start from the beginning

        except Exception as e:
            print("Error in vara_data:", str(e))
            vara_socket_ready = False  # Reset the socket_ready flag to indicate a disconnected state
            time.sleep(1)  # Wait for a while before attempting to reconnect
            socket = connect_vara_socket()  # Reestablish the connection
            vara_socket_ready = True  # Set the flag to indicate that the socket is ready

if __name__ == "__main__":
    connect_tnc_socket()
    connect_vara_socket()

    # Create a thread and start it
    tnc_thread = threading.Thread(target=tnc_data, args=(tnc_socket,))
    tnc_thread.start()
    
    # Create a thread and start it
    vara_thread = threading.Thread(target=vara_data, args=(vara_socket,))
    vara_thread.start()    
