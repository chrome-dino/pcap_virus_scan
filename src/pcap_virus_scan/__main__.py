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
    group1.add_argument("-k", "--key", help="virus total api key",required=False)
    group1.add_argument("-r", "--rules", help="yara rules file",required=False)
    group2.add_argument("-y", "--yara", help="scan objects with yara", action=argparse.BooleanOptionalAction,required=False)
    parser.add_argument("-x", "--executables", help="only scan for executable files", action=argparse.BooleanOptionalAction,required=False)
    group2.add_argument("-v", "--virus_total", help="submit objects to virus total", action=argparse.BooleanOptionalAction,required=False)

    mode_whitelist = ['http','smb','tftp','imf']



    args = parser.parse_args()
    if args.mode not in mode_whitelist:
        print('Export mode must be one of http, smb, tftp, imf.')
        exit(-1)
    if args.key and not args.virus_total or args.virus_total and not args.key:
        print('Must use both the virus total flag and the api key flag')
        exit(-1)
    if args.yara and not args.rules or args.rules and not args.yara:
        print('Must use both the yara total flag and the rules flag')
        exit(-1)
    scan = pcap_virus_scan.PcapVirusScan(pcap=args.file,mode=args.mode,key=args.key,rules=args.rules,yara=args.yara,virus_total=args.virus_total,executables=args.executables)
    scan.run()
    
if __name__ == "__main__":
    main()
    
