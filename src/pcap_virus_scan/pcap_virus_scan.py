import os
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi
import yara


class PcapVirusScan():
    def __init__(self, pcap, mode, key=None, rules=None, yara=False, virus_total=False):
        # Intialize member variables
        self.pcap = pcap
        self.mode = mode
        self.key = key
        self.rules = rules
        self.yara = yara
        self.virus_total = virus_total


    def export_objects(self):
        # clear export obj directory
        for root, dirs, files in os.walk('.\\pcap_virus_scan\\src\\pcap_virus_scan\\export_objects'):
            for file in files:
                if file == 'README':
                    continue
                os.remove(os.path.join(root,file))

        #use tshark to extract downloaded objects
        os.system('cmd /k "tshark -r ' + self.pcap + ' --export-objects ' + self.mode + ', .\\pcap_virus_scan\\src\\pcap_virus_scan\\export_objects"')


    def yara(self):
        rules = yara.compile(filepath=self.rules)
        print('##########################################################')
        print('YARA REPORT')
        print('##########################################################')
        print('')
        for root, dirs, files in os.walk('.\export_objects'):
            for file in files:
                print('----------------------------------------------------------')
                print('Scan for File: ' + file)
                print('----------------------------------------------------------')
                matches = rules.match(os.path.join(root,file))
                
                if not matches:
                    print('No matches detected')
                else:
                    for match in matches:
                        print('Rule: ' + match['rule'])
                        if 'namespace' in match:
                            print('Namespace: ' + match['namespace'])
                        
                        if 'tag' in match and match['tags']:
                            tag = ''
                            for t in match['tags']:
                                tag += t + ', '

                            print('Tags: ' + tag[:len(tag)-2])

                        if 'meta' in match:
                            print('Meta: ' + match['meta'])
                        

                print('')
                print('')


    def virus_total(self,hashes):
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
            print('Detection Rate: ' + str(response['results']['positives']) + '/' + str(response['results']['negatives']))
            print('----------------------------------------------------------')
            for key in response['results']['scans'].keys:
                vt_submission = response['results']['scans'][key]

                print('Source: ' + key)
                print('Detected: ' + str(vt_submission['detected']))
                if vt_submission['detected']:
                    print('filename: ' + vt_submission['result'])
                print('Update: ' + vt_submission['update'])
            print('')
            print('')

    @staticmethod
    def get_hash():
        hashes = []
        for root, dirs, files in os.walk('.\\pcap_virus_scan\\src\\pcap_virus_scan\\export_objects'):
            for file in files:
                if file == 'README':
                    continue
                hashes.append({'filename':file,'md5':hashlib.md5(open(file,'rb').read()).hexdigest()})

        return hashes


    def run(self):
        if self.virus_total:
            hashes = self.export_object()
            self.virus_total(hashes)
        elif self.yara:
            self.yara()
            
        
