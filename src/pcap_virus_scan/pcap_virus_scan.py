import os
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi
import yara
import subprocess

EXECUTEABLE_EXT = ['.apk','.cmd','.run','.exe','.ipa','bin','.bat','.app','.cgi','.ps1','vbs']

class PcapVirusScan():
    def __init__(self, pcap, mode, key=None, rules=None, yara=False, virus_total=False,executables=False):
        # Intialize member variables
        self.pcap = pcap
        self.mode = mode
        self.key = key
        self.rules = rules
        self.yara = yara
        self.virus_total = virus_total
        self.executables = executables


    def export_objects(self):
        # clear export obj directory
        for root, dirs, files in os.walk('.\\pcap_virus_scan\\src\\pcap_virus_scan\\export_objects'):
            for file in files:
                if file == 'README':
                    continue
                os.remove(os.path.join(root,file))

        #use tshark to extract downloaded objects
        process=subprocess.Popen('tshark -r ' + self.pcap + ' --export-objects ' + self.mode + ',\".\\pcap_virus_scan\\src\\pcap_virus_scan\\export_objects\"',shell=True,stdout=subprocess.PIPE)
        process.wait()

    def yara_mode(self):
        rules = yara.compile(filepath=self.rules)
        print('##########################################################')
        print('YARA REPORT')
        print('##########################################################')
        print('')
        for root, dirs, files in os.walk('.\pcap_virus_scan\src\pcap_virus_scan\export_objects'):
            for file in files:
                if self.executables:
                    if os.path.splitext(file)[1] not in EXECUTEABLE_EXT:
                        continue
                if file == 'README':
                    continue
                print('----------------------------------------------------------')
                print('Scan for File: ' + file)
                print('----------------------------------------------------------')
                matches = rules.match(os.path.join(root,file))
                
                if not matches:
                    print('No matches detected')
                else:
                    for match in matches:
                        print('Rule: ' + match.rule)
                        if match.namespace:
                            print('Namespace: ' + match.namespace)
                        
                        if match.tags:
                            tag = ''
                            for t in match.tags:
                                tag += t + ', '

                            print('Tags: ' + tag[:len(tag)-2])

                        if match.strings:
                            stri = ''
                            for t in match.strings:
                                stri += t[2].decode('ascii') + ', '

                            print('Strings: ' + stri[:len(stri)-2])
                        if match.meta:
                            print('Meta: ' + match.meta)
                        

                print('')
                print('')


    def virus_total_mode(self,hashes):
        vt = VirusTotalPublicApi(self.key)
        print('##########################################################')
        print('VIRUS TOTAL REPORT')
        print('##########################################################')
        print('')
        for hash in hashes:
            response = vt.get_file_report(hash['md5'])
            if response['response_code'] != 200:
                print('ERROR: Failed to get Virus Total report')
                exit(-1)

            print('----------------------------------------------------------')
            print('Scan for File: ' + hash['filename'])
            print('Scan Date: ' + response['results']['scan_date'])
            print('MD5:' + response['results']['md5'])
            print('SHA256:' + response['results']['sha256'])
            print('Detection Rate: ' + str(response['results']['positives']) + '/' + str(response['results']['total']))
            print('----------------------------------------------------------')
            for key in response['results']['scans']:
                vt_submission = response['results']['scans'][key]

                print('Source: ' + key)
                print('\tDetected: ' + str(vt_submission['detected']))
                if vt_submission['detected']:
                    print('\tfilename: ' + vt_submission['result'])
                print('\tUpdate: ' + vt_submission['update'])
                print('')
            print('')
            print('')

    def get_hash(self):
        hashes = []
        for root, dirs, files in os.walk('.\\pcap_virus_scan\\src\\pcap_virus_scan\\export_objects'):
            for file in files:
                if file == 'README':
                    continue
                if self.executables:
                    if os.path.splitext(file)[1] not in EXECUTEABLE_EXT:
                        continue 
                hashes.append({'filename':file,'md5':hashlib.md5(open('.\\pcap_virus_scan\\src\\pcap_virus_scan\\export_objects\\' + file,'rb').read()).hexdigest()})

        return hashes


    def run(self):
        self.export_objects()
        if self.virus_total:
            hashes = self.get_hash()
            self.virus_total_mode(hashes)
        elif self.yara:
            self.yara_mode()
            
        
