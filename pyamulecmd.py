import cmd
import ec
import getpass
import sys

prog_name = "pyamulecmd"
prog_ver  = "0.1"

host = "localhost"
port = 4712

class REPL(cmd.Cmd):
    def __init__(self):
	cmd.Cmd.__init__(self)
	self.prompt = "> "
	self.intro = "Welcome to %s %s" % (prog_name, prog_ver)
	self.ec = None
    def preloop(self):
	passwd = getpass.getpass("Password: ")
	try:
	    self.ec = ec.conn(passwd, host, port, prog_name, prog_ver)
	except ec.ConnectionFailedError:
	    print("Connection failed")
	    sys.exit()
    def do_quit(self, arg):
	sys.exit()
    def do_exit(self, arg):
	sys.exit()
    def do_EOF(self, arg):
	sys.exit()
    def do_connect(self, arg):
	self.ec.connect()
    def do_disconnect(self, arg):
	self.ec.disconnect()
    def do_shutdown(self, arg):
	self.ec.shutdown()
	sys.exit()

def main():
    repl = REPL()
    repl.cmdloop()

if __name__ == "__main__":
    main()