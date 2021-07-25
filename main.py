import socket, argparse, queue
from threading import Thread

class Worker(Thread):
	def __init__(self, target, q, *args, **kwargs):
		self.t = target
		self.q = q
		super().__init__(*args, **kwargs)
	def run(self):
		while True:
			try:
				work = self.q.get(timeout=1)
			except queue.Empty:
				return
			
			self.scan(work)
			self.q.task_done()

	def scan(self, port):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(TIMEOUT)
		if s.connect_ex((self.t, port))==0:
			print(f'[+] Port TCP/{port} \topen!' + f' \n\t└ {self.get_banner(port)}' if BANNERS else '')
		else:
			print(f'[+] Port TCP/{port} \tclosed!')
	
	def get_banner(self, port):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(TIMEOUT)
		try:
			s.connect((self.t, port))
			data = s.recv(1024).decode().split('\n')[0]
			s.close()
			return str(data)
		except:
			return "No banner available"

def get_arguments():
	"""Get arguments from the command line"""
	parser = argparse.ArgumentParser()
	
	parser.add_argument("target", help="The target IP Address")

	parser.add_argument('-p', '--port', dest='ports', help='Ports to analize. Define the range usind "-" or separe the ports using "," (Default: 1-100)', default='1-100')
	
	parser.add_argument('-t', '--timeout', dest='timeout', help='Response timeout in seconds (Default: 5)', default='5')

	parser.add_argument('-b', '--banners', dest='banners', help='Turns on banner detection (Default: false)', action="store_true")

	options = parser.parse_args()
	if not options.target:
		options = None
	return options

def main(target, ports, timeout, detect_banners):
	global TIMEOUT, THREADS_NUM, BANNERS
	TIMEOUT = timeout
	THREADS_NUM = 20
	BANNERS = detect_banners
	q = queue.Queue()

	if ',' in ports:
		ports = ports.split(',')
		for port in ports:
			ranges = [list(map(lambda x: int(x), port.split('-')))]
			for port_range in ranges:
				while port_range[0] <= port_range[1]:
					q.put_nowait(port_range[0])
					port_range[0]+=1
			for _ in range(THREADS_NUM):
				Worker(target, q).start()
			q.join()
	else:
		port_range = list(map(lambda x: int(x), ports.split('-')))
		
		while port_range[0] <= port_range[1]:
			q.put_nowait(port_range[0])
			port_range[0]+=1
		for _ in range(THREADS_NUM):
			Worker(target, q).start()
		q.join()


if __name__=='__main__':
	args = get_arguments()
	if args:
		target = str(args.target)
		ports = str(args.ports)
		timeout = str(args.timeout)
		banners = str(args.banners)
		main(target, ports, int(timeout), banners)
	else:
		target = input('[>] Target address: ')
		ports = input('[>] Port/Ports range: ')
		timeout = input('[>] Timeout: ')
		main(target, ports, int(timeout))