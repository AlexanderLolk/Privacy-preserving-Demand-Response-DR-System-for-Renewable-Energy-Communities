from src.utils.procedures import Procedures
from src.utils.private_key_proof import schnorr_NIZKP_verify
from src.utils.elgamal_dec_proof import verify_correct_decryption
import random

class DSO:
    """ 
    Represents the Distribution System Operator (DSO).
    
    The DSO is the central authority in this system. It is responsible for:
     - Generating the threshold encryption parameters.
     - Registering and verifying all participants (Smart Meters, Aggregators, DR Aggregators).
     - Defining the parameters for Demand Response (DR) events.
     - Generating the "Noisy List" (decoy zero-reports) to ensure privacy set size.
     - Distributing secret key shares to the Aggregators.
    """
    def __init__(self, init_id="DSO", pp=None):
        """
        Initializes the DSO entity.
        
        Generates:
        - Signing Key Pair (sk, pk) for authenticating DSO messages.
        - Threshold Encryption Key Pair (ek, shares) for the system-wide ElGamal cryptosystem.
        """
        self.pro = Procedures()
        pp = self.pro.pub_param()
        self.registered_sm = []
        self.registered_agg = []
        self.registered_dr = []
        self.agg_ek = {}
        
        #  SKeyGen(id, pp) -> ((id, (pk, pp, proof)), sk)
        ((self.id, (self.pk, self.pp, self.s_proof)), self.__sk) = self.pro.skey_gen(init_id, pp)
        
        # Generate the main encryption key for the system and the shares for the aggregators
        ((self.ek, self.thresh_params, self.e_proof), self.__key_shares) = self.pro.ekey_gen(pp)
        
        self.i = 0

    def get_threshold_params(self):
        """Return the threshold parameters for decryption."""
        return self.thresh_params

    def verify_smartmeter(self, sm_info):
        """
        Verifies every smart meter (users) and adds it into a registered list.
        
        It checks the Schnorr Non-Interactive Zero-Knowledge Proof (NIZKP) included 
        in the request to ensure the Smart Meter actually owns the private key 
        corresponding to the public key it claims.

        Args:
            sm_info (tuple): (id, (pk, pp, proof))

        Returns:
            bool: True if verification succeeds and SM is registered; False otherwise.
        """

        sm_id, val = sm_info
        # val = (pk, pp, proof)
        if schnorr_NIZKP_verify(val[0], val[1], val[2]):
            self.registered_sm.append((sm_id, val))
        else:
            raise ValueError("failed to verify smart meter")
    
    def verify_aggregator(self, agg_info):
        """
        Verifies the Energy aggregator's NIZKP proof and adds it (if True) into a registered list.

        Args:
            agg_info (tuple): (id, (pk, pp, proof))

        Returns:
            bool: True if verification succeeds and Aggregator is registered.
        """
        agg_id, val = agg_info
        
        if schnorr_NIZKP_verify(val[0], val[1], val[2]):
            self.registered_agg.append((agg_id, val))
        else:
            raise ValueError("failed to verify aggregator")
    
    def verify_dr_aggregator(self, dr_info):
        """
        Verifies the DR aggregator's NIZKP proof and adds it (if True) into a registered list.

        Args:
            dr_info (tuple): (Identity_String, (Public_Key, Public_Params, Proof_of_Knowledge))

        Returns:
            bool: True if verification succeeds and DR Aggregator is registered.
        """
        dr_id, val = dr_info
        # val = (pk, pp, proof) 
        if schnorr_NIZKP_verify(val[0], val[1], val[2]):
            self.registered_dr.append((dr_id, val))
        else:
            raise ValueError("failed to verify dr aggregator")
    
    def calculate_target_reduction():
        """ 
        Static method to define the parameters for the current Demand Response event.
        
        Placeholder values.¨

        Returns:
            tuple: (List_of_Params, Target_Reduction_Integer)
        """
        p = "1"
        phi = "0.05"
        R = "3"
        Ø = "4"
        E = "0.1"
        ts = "6"
        te = "7"
        delta_Q = "8"
        
        dr_param = [p, phi, R, Ø, E, ts, te, delta_Q]
        target_reduction_value = 11
        return dr_param, target_reduction_value

    def generate_noisy_list(self):
        """ 
        Generates the Noisy List of encrypted zero-reports.
        
        The list contains encryptions of 0 and the amount of target reduction values from
        calculate_target_reduction() that are then mixed in with real user reports.
        This ensures that even if only a few users participate, the total anonymity set 
        remains large enough to protect them.

        Returns:
            tuple: (List_of_Encrypted_Values, Signature_on_List)
        """
        _, target_reduction = DSO.calculate_target_reduction()

        max_noise = target_reduction
        zero_noise = random.randint(1, max_noise)

        values = []
        for i in range(max_noise):
            values.append(i)
        
        for i in range(zero_noise):
            values.append(0)

        random.shuffle(values)

        # print(f"\n\nNoisy Target Reduction list: {values} \n\n")

        enc_TR = [self.pro.ahe.encrypt_single(self.ek, val) for val in values]
        signature_TR = self.pro.sig.schnorr_sign(self.__sk, self.pp, str(enc_TR))

        return enc_TR, signature_TR

    def get_public_key(self):
        """ 
        The DSO's signing public key pk with pp and proof.

        Returns:
            tuple: (Public_Key, Public_Params, Proof)
        """
        return (self.pk, self.pp, self.s_proof)
    
    def get_encryption_key(self):
        """ 
        The DSO's Encryption key ek with pp and proof.

        Returns:
            tuple: (Encryption_Key_Point, Public_Params, Proof_of_Decryption_Capability)
        """
        return (self.ek, self.pp, self.e_proof)
    
    def set_agg_encryption_key(self, agg, dr_agg=False):
        """
        Stores the individual encryption keys of the Aggregators as aggs = [(id, ek)].
        
        Args:
            agg (tuple): tuple of (id, tuple(ek, pp, proof) signature) tuples.
        """
        id, (ek, pp, proof), signature = agg
        message_to_verify = id + str(ek.x) + str(ek.y)

        pk = None
        if dr_agg == False:
            for agg_id, val in self.registered_agg:
                if agg_id == id:
                    pk = val[0]

        elif dr_agg == True:
            for dr_id, val in self.registered_dr:
                if dr_id == id:
                    pk = val[0]
                    break

        if pk is None or pp is None:
            raise ValueError("pk could not be found in registy")
        if not self.pro.sig.schnorr_verify(pk, pp, message_to_verify, signature):
            raise ValueError("dso failed to verify aggregator")
        if not verify_correct_decryption(ek, pp, proof):
            raise ValueError("dso failed to verify aggregator's proof of correct decryption")

        self.agg_ek[id] = ek  

    def encrypt_dk_and_send_to_agg(self, agg_id):
        """
        Distributes a Threshold Decryption Key Share to a specific Aggregator.

        Note
        In a real deployment, this is done over a secure channel (TLS/SSL).
        Currently, it returns the raw scalar key (int) share to simulate how it would work in
        a local environment. (encryption isnt inserted here since ElGamal would turn the scalar
        keyshare into a point, making it unusable for threshold decryption without solving discrete log)

        Args:
            agg_id (str): The ID of the aggregator requesting the share.

        Returns:
            tuple: (x position, The private key share (Scalar), Signature on the share)
        """
        # print("[NOT IMP] In dso.encrypt_dk_and_send_to_agg: un-encrypted dso dk given to agg (supposed to be a private channel over SSL)")

        # TODO DOES NOT WORK
        # # check if keys are generated
        # if not hasattr(self, 'key_shares') or not self.key_shares:
        #     return None
         
        # # check if we already assigned a share to this id (initialize map if it doesnt exist)
        # if not hasattr(self, 'assigned_shares_map'):
        #     self.asssigned_shares_map = {}

        # if agg_id in self.asssigned_shares_map:
        #     # return existing share for this agg
        #     return self.asssigned_shares_map[agg_id]

        # # assign a new share
        # # use length of map to determine next index
        # next_index = len(self.asssigned_shares_map)

        # if next_index >= len(self.key_shares):
        #     return None # if no more key shares available for the specific agg
        
        # share = self.key_shares[next_index]
        # self.asssigned_shares_map[agg_id] = share

        # return share

        # stupid but works
        share = self.__key_shares[self.i]
        self.i += 1
        # encrypt the share with the agg's encryption key
        x = share.x
        y = share.y
        # print(f"DSO encrypting dk share {x}, {y} for agg {agg_id} with ek {self.agg_ek[agg_id]}")
        sig_share = self.pro.sig.schnorr_sign(self.__sk, self.pp, str((x, y)))
        enc_share = self.pro.ahe.enc(self.agg_ek[agg_id], y)


        return x, enc_share, sig_share

    def sign_registered_lists(self):
        """
        Cryptographically signs the lists of all Smart meters and both aggregators.
        
        This allows aggregators to verify that a Smart Meter 
        participating in the protocol is legitimate and registered with the DSO.

        Returns:
            tuple: (SM_List, SM_Sigs, Agg_List, Agg_Sigs, DR_List, DR_Sigs)
        """
        sm_msg_list = [sm_id for sm_id, _ in self.registered_sm]
        agg_msg_list = [agg_id for agg_id, _ in self.registered_agg]
        dr_msg_list = [dr_id for dr_id, _ in self.registered_dr]

        sm_signatures = self.pro.sig.schnorr_sign_list(self.__sk, self.pp, sm_msg_list)
        agg_signatures = self.pro.sig.schnorr_sign_list(self.__sk, self.pp, agg_msg_list)
        dr_signatures = self.pro.sig.schnorr_sign_list(self.__sk, self.pp, dr_msg_list)

        return (self.registered_sm, sm_signatures, self.registered_agg, agg_signatures, self.registered_dr, dr_signatures)