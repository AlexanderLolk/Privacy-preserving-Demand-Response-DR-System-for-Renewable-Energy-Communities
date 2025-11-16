
class PrivateBoard:
    
    def __init__(self):
        pass
    
    def publish_sm_reports(self, sm_reports):
        print("[NOT IMP] in privateboard: Publish anonym reports on PBB")
        self.sm_reports = sm_reports
        #[(pk, (t, cts, signature))] = sm_reports
        
        # pks = [report[0] for report in sm_reports]
        # msgs = [str((report[1][0], report[1][1])) for report in sm_reports]
        # signatures = [report[1][2] for report in sm_reports]

        # # pk, sec_params, msg_list, signatures
        # if not schnorr_verify_list(self.pk[0], self.pk[1], msgs, signatures):
        #     print("Smartmeters were not verified")
        
        # print("Published smartmeter reports:")
        # self.sm_reports = sm_reports
        
        
    def publish_anonym_reports(self, anonym_reports):
        
        for pk, ct, t, proof in anonym_reports:
            print("[NOT IMP] in privateboard: check proof for anonym in PBB")
            
        self.anonym_reports = anonym_reports

    