from netscan import Netscan
import argparse

class Main:

    def main(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-t', '--target', dest='target', help='Target IP Address/Adresses')
        options = parser.parse_args()
        if not options.target:
            parser.error("[-] Please specify an IP Address or Addresses, use --help for more info.")
        return options


if __name__ == '__main__':
   option = Main().main()
   scanned_output = Netscan().scan(option.target)
   Netscan().display_result(scanned_output)
