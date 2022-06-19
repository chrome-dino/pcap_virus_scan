import argparse
import pcap_virus_scan
import sys

def main():
    parser = argparse.ArgumentParser()

    # cmd line args

    group1 = parser.add_mutually_exclusive_group(required=True)
    group2 = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("-f", "--file", help="pcap file to be analyzed",required=True)
    parser.add_argument("-m", "--mode", help="protocol to export objects from. Choose from http, smb, tftp, imf",required=True)
    group1.add_argument("-k", "--key", help="virus total api key",required='-v' in sys.argv)
    group1.add_argument("-r", "--rules", help="yara rules file",required='-y' in sys.argv)
    group2.add_argument("-y", "--yara", help="scan objects with yara", action=argparse.BooleanOptionalAction,required='-r' in sys.argv)
    group2.add_argument("-v", "--virus_total", help="submit objects to virus total", action=argparse.BooleanOptionalAction,required='-k' in sys.argv)

    mode_whitelist = ['http','smb','tftp','imf']



    args = parser.parse_args()
    if args.mode not in mode_whitelist:
        print('Export mode must be one of http, smb, tftp, imf.')
        exit(-1)

    scan = pcap_virus_scan.PcapVirusScan(pcap=args.file,mode=args.mode,key=args.key,rules=args.rules,yara=args.yara,virus_total=args.virus_total)
    scan.run()
    
if __name__ == "__main__":
    main()
