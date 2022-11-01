import parser
import keygen
import dot11decrypt
import sys


if __name__ == '__main__':
    ssid = sys.argv[1]
    passphrase = sys.argv[2]
    
    parser = parser.PARSER()
    parser.get_info()
    keygen = keygen.KEY_GENERATOR(parser, ssid, passphrase)
    pmk = keygen.gen_PMK()
    ptk = keygen.gen_PTK(pmk)
    mics = keygen.gen_mics(ptk, parser.data) 
    keygen.verify_mics(mics, parser)
    dot11decrypt.dot11i_decrypt(parser, ptk[32:48])
