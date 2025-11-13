
class PrivateBoard:
    
    def __init__(self):
        pass
    
    def publish_anonym(self, anonym_data):
        print("Anonym not implemented")
        
        
    def publish_sm_reports(self, sm_reports):
        print(f"Publish anonym reports on PBB (not implemented)")
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