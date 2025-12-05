class PrivateBoard:
    """ 
    Args: TODO
    """
    def __init__(self):
        pass
        
    # Anonym user consumption reports from 
    def publish_anonym_reports(self, anonym_reports):
        """
        Args:
          anonym_reports: tuple[EcPt, tuple[EcPt, EcPt], int, str(placeholder)]
        """
        self.participants = []
        self.ct_t = {}  # pk' -> (t, ct_c, σ)
        
        for pk_prime, ct, t, proof in anonym_reports:
            self.participants.append(pk_prime)
            
            pk_key = str((pk_prime.x, pk_prime.y))
            self.ct_t[pk_key] = (t, ct, proof)
            print("[NOT IMP] in privateboard: check proof for anonym in PBB")

        self.anonym_reports = anonym_reports

    # pseudo-anonymous identity
    def get_participants(self):
        """ 
        return:
            list[EcPt]
        """
        return self.participants