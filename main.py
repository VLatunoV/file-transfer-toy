import argparse
import socket
import threading
import os
import struct
import time

Address = tuple[str, int]

def make_options():
	params = argparse.ArgumentParser(
		description='Send or receive files with a partner.',
		formatter_class=argparse.RawTextHelpFormatter
	)
	# params.add_argument(
	# 	'--name',
	# 	help='Friendly name for your partner to see. :)',
	# 	required=False
	# )
	params.add_argument(
		'-t', '--type',
		help=
		'> host - Wait for the partner to connect to you.\n'
		'> join - Connect to a partner.',
		choices=['host', 'join'],
		required=False
	)
	params.add_argument(
		'-a', '--ip',
		help='IP address to connect to. Not needed if hosting.',
		required=False
	)
	params.add_argument(
		'-p', '--port',
		help='Port for the connection.',
		type=int,
		required=False
	)
	return params.parse_args()

def validate_ip(ip):
	if ip=='localhost':
		return True
	octets = ip.split('.')
	if len(octets) != 4:
		return False
	try:
		octets = list(map(int, octets))
		if not all([0 <= x < 256 for x in octets]):
			return False
	except:
		return False
	return True

def validate_options(args):
	if args.type is None:
		args.type = 'join'
	print(f'{args.type.capitalize()}ing session...')
	# if args.name is None:
	# 	args.name = input('Your name: ').capitalize()
	if args.ip is None and args.type == 'join':
		is_valid = False
		while not is_valid:
			args.ip = input('Connect to IP: ')
			is_valid = validate_ip(args.ip)
			if not is_valid:
				print("[Error] Invalid IP address!")
	if args.port is None:
		is_valid = False
		while not is_valid:
			args.port = input('Port: ')
			try:
				args.port = int(args.port)
				if 0 < args.port < 65536:
					is_valid = True
			except:
				pass
			if not is_valid:
				print("[Error] Invalid port number!")
	return args

class Controller:
	def __init__(self, args):
		# self.name = args.name
		self.ip = args.ip
		self.port = args.port
		self.is_server = (args.type == 'host')
		self.sock = None
		self.stopping = False

	def make_connection(self) -> tuple[socket.socket, Address]:
		temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		if self.is_server:
			print(f"Waiting for connection on port:{self.port}...")
			temp_sock.bind(('', self.port))
			temp_sock.listen()
			self.sock, partner_address = temp_sock.accept()
			self.ip, self.port = self.sock.getsockname()
			temp_sock.close()
		else:
			print(f"Connecting to {self.ip}:{self.port}...")
			partner_address = (self.ip, self.port)
			temp_sock.connect(partner_address)
			self.sock = temp_sock
			self.partner_address = partner_address
		print(f"Connection established with {self.ip}:{self.port}")

	def stop(self):
		self.stopping = True
		self.sock.close()
		print("Disconnected.")

class Command:
	def __init__(self, cmd, desc):
		self.cmd = cmd
		self.desc = desc

def format_size(size: int):
	units = ['B', 'KB', 'MB', 'GB']
	u = 0
	while u+1 < len(units) and size > 1000:
		size = size / 1024
		u += 1
	return f'{size:.2f} {units[u]}'

def send_file(sock: socket.socket, file, filename: str):
	file.seek(0, os.SEEK_END)
	file_size = file.tell()
	file.seek(0, os.SEEK_SET)

	filename_bytes = bytes(filename.encode('utf-8'))
	filename_size = len(filename_bytes)

	# Send filename length and data
	header_data = struct.pack('!I', filename_size) + filename_bytes
	sent = sock.send(header_data)
	if sent != len(header_data):
		raise ConnectionError("Failed to send header for file transfer")

	# Send file size
	sent = sock.send(struct.pack('!I', file_size))

	# Send file data
	print_msg = f'Sending file "{filename[:20]}"' + ' [{} / {} ## {:.2f}%]   '
	total_size_string = format_size(file_size)
	last_print_time = time.time()
	read_block_size = 1024 * 1024 # 1MB
	total_sent = 0
	while total_sent < file_size:
		to_read = min(read_block_size, file_size - total_sent)
		data = memoryview(file.read(to_read))
		if not data:
			break  # EOF
		while True:
			try:
				sent = sock.send(data)
			except BlockingIOError:
				continue
			else:
				total_sent += sent
				curr_time = time.time()
				if curr_time - last_print_time > 0.5:
					print(print_msg.format(format_size(total_sent), total_size_string, 100.0 * (total_sent / file_size)), end='\r')
					last_print_time = curr_time
				if sent < len(data):
					data = data[sent:]
				else:
					break
	print(print_msg.format(format_size(total_sent), total_size_string, 100.0 * (total_sent / file_size)))

def send_func(controller: Controller):
	sock = controller.sock
	commands = [
		Command('exit', 'Exit'),
		Command('end', 'Exit'),
		Command('send', 'send FILE_NAME - Sends the file to your partner.'),
		Command('?', 'Print this help.')
	]
	help_text = '\n'.join([f'{x.cmd.ljust(10)} {x.desc}' for x in commands])
	while not controller.stopping:
		cmd = input('> ')
		if controller.stopping:
			break
		match cmd:
			case '?':
				print(help_text)
			case 'exit' | 'end':
				controller.stop()
		if cmd.startswith('send'):
			filepath = cmd[4:].strip(' \"\'')
			if not os.path.exists(filepath):
				print(f'[ERROR] File "{filepath}" does not exist')
				continue
			if not os.path.isfile(filepath):
				print(f'[ERROR] Path "{filepath}" is not a file')
				continue
			try:
				with open(filepath, 'rb') as f:
					filename = os.path.basename(filepath)
					send_file(sock, f, filename)
			except Exception as e:
				print(str(type(e)) + str(e))
				controller.stop()

def make_filename(filepath: str):
	basedir = os.path.dirname(filepath)
	filename, ext = os.path.basename(filepath).rsplit('.', 1)
	result = filepath
	idx = 1
	while os.path.exists(result):
		result = os.path.join(basedir, filename + f'_({idx}).' + ext)
		idx += 1
	return result

def recv_func_inner(controller):
	sock: socket.socket = controller.sock
	basedir = os.path.dirname(__file__)
	recv_folder = os.path.join(basedir, 'received')
	if os.path.exists(recv_folder):
		if not os.path.isdir(recv_folder):
			raise RuntimeError(f'Cannot create folder "{recv_folder}". Such a file exists')
	else:
		os.mkdir(recv_folder)

	read_block_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
	while not controller.stopping:
		# Check if any data is available
		while not controller.stopping:
			try:
				dummy = sock.recv(4, socket.MSG_PEEK)
				if not dummy:
					controller.stop()
				break
			except Exception as e:
				print(str(type(e)) + str(e))
				break
		if controller.stopping:
			break

		# Filename length
		filename_len = sock.recv(4)
		if len(filename_len) != 4:
			raise ConnectionError("Failed to receive filename length")
		filename_len, = struct.unpack("!I", filename_len)

		# Filename
		filename = sock.recv(filename_len)
		if len(filename) != filename_len:
			raise ConnectionError("Failed to receive filename")
		filename = filename.decode('utf-8')

		# File length
		file_size = sock.recv(4)
		if len(file_size) != 4:
			raise ConnectionError("Failed to receive file_len length")
		file_size, = struct.unpack("!I", file_size)

		# File data
		print_message = f'Downloading file "{filename[:20]}"' + ' [{} / {} ## {:.2f}%]   '
		total_size_string = format_size(file_size)
		last_print_time = time.time()
		filepath = make_filename(os.path.join(recv_folder, filename))
		with open(filepath, 'wb') as f:
			total_recv = 0
			while total_recv < file_size:
				read_bytes = min(read_block_size, file_size - total_recv)
				while True:
					try:
						data = sock.recv(read_bytes)
					except BlockingIOError:
						continue
					else:
						if not data:
							raise ConnectionError("Connection closed")
						f.write(data)
						total_recv += len(data)
						curr_time = time.time()
						if curr_time - last_print_time > 0.5:
							print(print_message.format(format_size(total_recv), total_size_string, 100.0 * (total_recv / file_size)), end='\r')
							last_print_time = curr_time
						break
		print(print_message.format(format_size(total_recv), total_size_string, 100.0 * (total_recv / file_size)))

def recv_func(controller: Controller):
	try:
		recv_func_inner(controller)
	except Exception as e:
		print(str(type(e)) + str(e))
		controller.stop()

if __name__ == '__main__':
	args = make_options()
	args = validate_options(args)
	
	controller = Controller(args)
	controller.make_connection()
	recver_thread = threading.Thread(target=recv_func, args=(controller,))
	recver_thread.start()
	try:
		send_func(controller)
	except:
		controller.stop()
	recver_thread.join()
