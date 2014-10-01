from pytun import TunTapDevice, IFF_TAP
import sys, os, logging, time
from optparse import OptionParser
from binascii import hexlify

from deamon import Daemon

from dpkt.ethernet import Ethernet 

##############################################

MODULE_NAME = 'tap-testing'
__version__ = '0.1'

##############################################

class TapDaemon(Daemon):
    def __init__(self, moduleName, options):
        self.moduleName=moduleName
        self.options = options
        self.logger = logging.getLogger(self.__class__.__name__)
        pidFile = "%s/%s.pid" % (self.options.pidDir, self.moduleName)
        Daemon.__init__(self, pidFile)

    #---------------------
    def run(self):
        """
        Method called when starting the daemon. 
        """
        try:
            logger.info("TapDaemon has started")
            tap0 = TunTapDevice(name="tap0", flags=IFF_TAP)
            tap0.hwaddr = '\x00\x11\x22\x33\x44\x55'
            tap0.addr = '192.168.0.1'
            tap0.dstaddr = '192.168.0.2'
            tap0.netmask = '255.255.255.0'
            tap0.mtu = 1500
            tap0.persist(True)
            tap0.up()
            logger.info("tap0 interface created")
        except:
            logger.exception("exception: ")
            
        try:
            tap1 = TunTapDevice(name="tap1", flags=IFF_TAP)
            tap1.hwaddr = '\x00\x11\x22\x33\x44\x66'
            tap1.addr = '192.168.1.1'
            tap1.dstaddr = '192.168.1.2'
            tap1.netmask = '255.255.255.0'
            tap1.mtu = 1500
            tap1.persist(True)
            tap1.up()
            logger.info("tap1 interface created")
        except:
            logger.exception("exception: ")
            
        try:
            while True:
                time.sleep(2)
                frame = Ethernet(dst="\x01\x02\x03\x04\x05\x06", src="\x0A\x0B\x0C\x0D\x0E\x0F", type = 0x9100, data = "\x11\x00\x00\x00\x33\x22\x00\x00"+"\x61"*40)
                tap0.write("\x11\x22\x33\x44" + str(frame))
                logger.info("Frame send to tap0")

                logger.info("Waiting for frame in tap1...")
                buf = tap1.read(tap1.mtu)
                logger.info("Received %s", hexlify(buf))
                logger.info("\n\n ---------------------------------------------------")
        except:
            logger.exception("exception: ")

        
if __name__ == "__main__":
    
    # optional command-line arguments processing
    usage="usage: %prog start|stop|restart [options]"
    parser = OptionParser(usage=usage, version="%prog " + __version__)
    parser.add_option("-p", "--pidDir", dest="pidDir", default='/tmp', help="directory for pid file")
    parser.add_option("-l", "--logDir", dest="logDir", default='.', help="directory for log file")
    parser.add_option("-i", "--iorDir", dest="iorDir", default='/tmp', help="directory for ior file")
    parser.add_option("-c", "--confDir", dest="confDir", default='.',    help="directory for config file")
    options, args = parser.parse_args()
    
    # I do a hack if configDir is default - './' could not point to local dir 
    if options.confDir == '.':
        options.confDir = sys.path[0]

    if 'start' in args[0]:
        # clear log file
        try:
            os.remove("%s/%s.log" % (options.logDir, MODULE_NAME))
        except: 
            pass          

    # creation of logging infrastructure
    logging.basicConfig(filename = "%s/%s.log" % (options.logDir, MODULE_NAME),
                        level    = logging.DEBUG,
                        format   = "%(levelname)s - %(asctime)s - %(name)s - %(message)s")
    logger = logging.getLogger(MODULE_NAME)

    # starting module's daemon
    daemon = TapDaemon(MODULE_NAME, options)
    
    # mandatory command-line arguments processing
    if len(args) == 0:
        print usage
        sys.exit(2)
    if 'start' == args[0]:
        logger.info('starting the module')
        daemon.start()
    elif 'stop' == args[0]:
        logger.info('stopping the module')
        daemon.stop()
    elif 'restart' == args[0]:
        logger.info('restarting the module')
        daemon.restart()
    else:
        print "Unknown command"
        print usage
        sys.exit(2)
                
    sys.exit(0)