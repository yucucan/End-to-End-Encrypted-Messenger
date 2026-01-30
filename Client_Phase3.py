import math
import time
import random
import sys
import json
import os
import requests

# Cryptography Imports
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_512, SHA3_256, SHA256, HMAC
from Crypto.Cipher import AES
from Crypto.Random import random as crypto_random
from kyber_py.kyber import Kyber1024

# -----------------------------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------------------------

API_URL = 'http://harpoon1.sabanciuniv.edu:9997'
stuID = 34218
stuIDB = 34218 # 34245 18007 34335 34401

# File names
IK_FILE = "IdentityKey_Phase3.json"
SPK_FILE = "SignedPreKey_Phase3.json"
OTK_FILE = "OneTimeKeys_Phase3.json"
PQOTK_FILE = "PQOneTimeKeys_Phase3.json"

# Curve Setup: Ed25519
curve = Curve.get_curve('Ed25519')
n = curve.order
P = curve.generator
field = curve.field

# Server's Identity Public Key
IKey_Ser_X_Hex = "0x2eef2e2656fb3d8c3c4932c679fbca121c2ea5fe26deecd800bc9311ef06f06"
IKey_Ser_Y_Hex = "0x17a8a7f452068d1157a974abc69cd5ae83d528936b4c1d8dab6095d28eeedcc0"
IKey_Ser = Point(int(IKey_Ser_X_Hex, 16), int(IKey_Ser_Y_Hex, 16), curve)


# -----------------------------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------------------------

def to_bytes(val, length=32):
    """Converts integer to bytes. Supports dynamic length if length=None."""
    if length is None:
        if val == 0: return b'\x00'
        length = (val.bit_length() + 7) // 8
    if val < 0: val = val % n
    return val.to_bytes(length, byteorder='big')


def KeyGen(curve):
    sA = crypto_random.randint(1, n - 2)
    QA = sA * P
    return sA, QA


def SignGen(message_bytes, sA, QA):
    h1 = SHA3_512.new(to_bytes(sA, 32)).digest()
    r_digest = SHA3_512.new(h1[32:] + message_bytes).digest()
    r_int = int.from_bytes(r_digest, 'big') % n
    R = r_int * P
    buff = to_bytes(R.x, 32) + to_bytes(R.y, 32) + to_bytes(QA.x, 32) + to_bytes(QA.y, 32) + message_bytes
    h2_digest = SHA3_512.new(buff).digest()
    h2_int = int.from_bytes(h2_digest, 'big') % n
    s = (r_int + (sA * h2_int)) % n
    return R, s


def SignVer(message_bytes, s, R, QA):
    # Dynamic length for verification (Server/Pseudo-Client compatibility)
    buff = (to_bytes(R.x, length=None) + to_bytes(R.y, length=None) +
            to_bytes(QA.x, length=None) + to_bytes(QA.y, length=None) +
            message_bytes)
    h2_digest = SHA3_512.new(buff).digest()
    h2_int = int.from_bytes(h2_digest, 'big') % n
    v1 = s * P
    v2 = R + (h2_int * QA)
    return v1 == v2


# -----------------------------------------------------------------------------
# FILE MANAGEMENT
# -----------------------------------------------------------------------------

def load_or_create_ik():
    if os.path.exists(IK_FILE):
        try:
            with open(IK_FILE, "r") as f:
                data = json.load(f)
                pri = int(data["pri_key"])
                return pri, pri * P, True
        except:
            pass
    print("Creating new Identity Key.")
    pri, pub = KeyGen(curve)
    with open(IK_FILE, "w") as f:
        json.dump({"pri_key": str(pri), "pub_x": str(pub.x), "pub_y": str(pub.y)}, f, indent=4)
    return pri, pub, False


def load_or_create_spk():
    if os.path.exists(SPK_FILE):
        try:
            with open(SPK_FILE, "r") as f:
                data = json.load(f)
                pri = int(data["pri_key"])
                return pri, pri * P, True
        except:
            pass
    print("Generating new SPK...")
    pri, pub = KeyGen(curve)
    with open(SPK_FILE, "w") as f:
        json.dump({"pri_key": str(pri), "pub_x": str(pub.x), "pub_y": str(pub.y)}, f, indent=4)
    return pri, pub, False


def load_or_create_otks():
    if os.path.exists(OTK_FILE):
        try:
            with open(OTK_FILE, "r") as f:
                data = json.load(f)
                return {int(k): {"pri": int(v["pri_key"]), "pub": int(v["pri_key"]) * P} for k, v in data.items()}, True
        except:
            pass
    return {}, False


def save_otks(otk_dict):
    serializable = {k: {"pri_key": str(v["pri"]), "pub_x": str(v["pub"].x), "pub_y": str(v["pub"].y)} for k, v in
                    otk_dict.items()}
    with open(OTK_FILE, "w") as f: json.dump(serializable, f, indent=4)
    print(f"Saved {len(otk_dict)} OTKs.")


def load_or_create_pqotks():
    if os.path.exists(PQOTK_FILE):
        try:
            with open(PQOTK_FILE, "r") as f:
                data = json.load(f)
                return {int(k): {"sk": bytes.fromhex(v["sk_hex"]), "pk": bytes.fromhex(v["pk_hex"])} for k, v in
                        data.items()}, True
        except:
            pass
    return {}, False


def save_pqotks(pqotk_dict):
    serializable = {k: {"sk_hex": v["sk"].hex(), "pk_hex": v["pk"].hex()} for k, v in pqotk_dict.items()}
    with open(PQOTK_FILE, "w") as f: json.dump(serializable, f, indent=4)
    print(f"Saved {len(pqotk_dict)} PQOTKs.")


# -----------------------------------------------------------------------------
# API WRAPPERS
# -----------------------------------------------------------------------------

def IKRegReq(R, s, x, y):
    mes = {'ID': stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    requests.put(f'{API_URL}/IKRegReq', json=mes)
    return True


def IKRegVerify(code):
    mes = {'ID': stuID, 'CODE': code}
    return requests.put(f'{API_URL}/IKRegVerif', json=mes).ok


def SPKReg(R, s, x, y):
    mes = {'ID': stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    requests.put(f'{API_URL}/SPKReg', json=mes)


def OTKReg(keyID, x, y, hmac_val):
    mes = {'ID': stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac_val}
    response = requests.put(f'{API_URL}/OTKReg', json=mes)
    return response.ok


def PQOTKReg(keyID, pqpk_hex, R, s):
    mes = {'ID': stuID, 'KEYID': keyID, 'PQOTKI': pqpk_hex, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    response = requests.put(f'{API_URL}/PQOTKReg', json=mes)
    return response.ok


def ExchangePartialKeys(z1x, z1y, R, s):
    msg = {'ID': stuID, 'z1.x': z1x, 'z1.y': z1y, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    print("Exchanging partial keys...")
    response = requests.get(f'{API_URL}/ExchangePartialKeys', json=msg)
    if response.ok:
        res = response.json()
        return res['z2.x'], res['z2.y'], res['z4.x'], res['z4.y']
    return None, None, None, None


def ExchangeXs(x1x, x1y, R, s):
    msg = {'ID': stuID, 'x1.x': x1x, 'x1.y': x1y, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    print("Exchanging x values...")
    response = requests.get(f'{API_URL}/ExchangeXs', json=msg)
    if response.ok:
        res = response.json()
        return res['x2.x'], res['x2.y'], res['x3.x'], res['x3.y'], res['x4.x'], res['x4.y']
    print("Error ExchangeXs:", response.text)
    return None, None, None, None, None, None


def BonusChecker(Kx, Ky):
    mes = {'ID': stuID, 'K.x': Kx, 'K.y': Ky}
    print("Sending message is: ", mes)
    response = requests.put(f'{API_URL}/BonusChecker', json=mes)
    if response.ok:
        try:
            print(response.json())
        except:
            print("Conference key accepted (No JSON response).")
    else:
        print(f"BonusChecker Failed: {response.text}")


def PseudoSendMsg(R, s):
    mes = {'ID': stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    print("Requesting pseudo-client messages...")
    requests.put(f'{API_URL}/PseudoSendMsg', json=mes)


def ReqMsg(R, s):
    mes = {'ID': stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    response = requests.get(f'{API_URL}/ReqMsg', json=mes)
    if response.ok:
        res = response.json()
        return (res["IDB"], res["OTKID"], res["MSGID"], int(res["MSG"]),
                int(res["IK.X"]), int(res["IK.Y"]),
                int(res["EK.X"]), int(res["EK.Y"]),
                res.get("PQKEYID"), res.get("PQCT", ""))
    return None


def ReqDelMsgs(R, s):
    mes = {'ID': stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    response = requests.get(f'{API_URL}/ReqDelMsgs', json=mes)
    if response.ok: return response.json().get("MSGID", [])
    return []


def Checker(stuIDB, msgID, decmsg):
    mes = {'IDA': stuID, 'IDB': stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    response = requests.put(f'{API_URL}/Checker', json=mes)
    try:
        res_json = response.json()
        if isinstance(res_json, dict):
            print(f"Checker: {res_json.get('message', res_json)}")
        else:
            print(f"Checker: {res_json}")
    except:
        print(f"Checker: {response.text}")


def ReqKeyBundle(target_id, R, s):
    mes = {'IDA': stuID, 'IDB': target_id, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    response = requests.get(f'{API_URL}/ReqKeyBundle', json=mes)
    if response.ok: return response.json()
    return None


def SendMsg(idB, otkid, msgid, msg, ek, pqkeyid, pqct):
    _, IK_Pub, _ = load_or_create_ik()
    mes = {
        "IDA": stuID, "IDB": idB, "OTKID": int(otkid), "MSGID": msgid, "MSG": msg,
        "IK.X": IK_Pub.x, "IK.Y": IK_Pub.y, "EK.X": ek.x, "EK.Y": ek.y,
        "PQOTKID": pqkeyid, "PQCT": pqct
    }
    requests.put(f'{API_URL}/SendMSG', json=mes)
    print(f"Sent Msg {msgid} to {idB}.")


def Status(R, s):
    mes = {'ID': stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    response = requests.get(f'{API_URL}/Status', json=mes)
    if response.ok: return response.json()
    return None


def ResetOTK(R, s):
    mes = {'ID': stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    requests.delete(f'{API_URL}/ResetOTK', json=mes)


def ResetSPK(R, s):
    mes = {'ID': stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    requests.delete(f'{API_URL}/ResetSPK', json=mes)


def ResetIK(rcode):
    mes = {'ID': stuID, 'RCODE': rcode}
    requests.delete(f'{API_URL}/ResetIK', json=mes)


# -----------------------------------------------------------------------------
# PROTOCOL LOGIC (PQXDH & KDF)
# -----------------------------------------------------------------------------

def PQXDH_Receiver(IK_B, EK_B, IK_A_Pri, SPK_A_Pri, OTK_A_Pri, PQSK_A, PQCT_hex):
    T1 = SPK_A_Pri * IK_B
    T2 = IK_A_Pri * EK_B
    T3 = SPK_A_Pri * EK_B
    T4 = OTK_A_Pri * EK_B

    PQCT = bytes.fromhex(PQCT_hex)
    SS = Kyber1024.decaps(PQSK_A, PQCT)

    U = (to_bytes(T1.x) + to_bytes(T1.y) + to_bytes(T2.x) + to_bytes(T2.y) +
         to_bytes(T3.x) + to_bytes(T3.y) + to_bytes(T4.x) + to_bytes(T4.y) +
         SS + b'WhatsUpDoc')
    return SHA3_256.new(U).digest()


def PQXDH_Sender(IK_B, SPK_B, OTK_B, IK_A_Pri, EK_A_Pri, PQPK_B_hex):
    T1 = IK_A_Pri * SPK_B
    T2 = EK_A_Pri * IK_B
    T3 = EK_A_Pri * SPK_B
    T4 = EK_A_Pri * OTK_B

    PQPK_B = bytes.fromhex(PQPK_B_hex)
    SS, PQCT = Kyber1024.encaps(PQPK_B)

    U = (to_bytes(T1.x) + to_bytes(T1.y) + to_bytes(T2.x) + to_bytes(T2.y) +
         to_bytes(T3.x) + to_bytes(T3.y) + to_bytes(T4.x) + to_bytes(T4.y) +
         SS + b'WhatsUpDoc')

    Ks = SHA3_256.new(U).digest()
    return Ks, PQCT.hex()


def KDF_Chain(K_root):
    K_enc = SHA3_256.new(K_root + b'JustKeepSwimming').digest()
    K_hmac = SHA3_256.new(K_root + K_enc + b'HakunaMatata').digest()
    K_next = SHA3_256.new(K_enc + K_hmac + b'OhanaMeansFamily').digest()
    return K_enc, K_hmac, K_next


def Decrypt_Message(msg_int, K_enc, K_hmac):
    msg_hex = hex(msg_int)[2:]
    if len(msg_hex) % 2 != 0: msg_hex = '0' + msg_hex
    try:
        msg_bytes = bytes.fromhex(msg_hex)
    except ValueError:
        return "INVALID_ENCODING", False

    if len(msg_bytes) < 41: return "INVALIDHMAC", False

    nonce = msg_bytes[:8]
    mac_received = msg_bytes[-32:]
    ciphertext = msg_bytes[8:-32]

    hmac_calc = HMAC.new(K_hmac, ciphertext, digestmod=SHA256).digest()
    if hmac_calc != mac_received: return "INVALIDHMAC", False

    cipher = AES.new(K_enc, AES.MODE_CTR, nonce=nonce)
    try:
        return cipher.decrypt(ciphertext).decode('utf-8'), True
    except:
        return "DECRYPTION_FAILED", False


def Encrypt_Message(plaintext, K_enc, K_hmac):
    cipher = AES.new(K_enc, AES.MODE_CTR)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    hmac_val = HMAC.new(K_hmac, ciphertext, digestmod=SHA256).digest()
    return int.from_bytes(nonce + ciphertext + hmac_val, 'big')


# -----------------------------------------------------------------------------
# FETCHING LOGIC
# -----------------------------------------------------------------------------

def fetch_and_decrypt(num_messages, R_sig, s_sig, IK_Pri, SPK_Pri, OTKs, PQOTKs, batch_name="Unknown"):
    print(f"\n--- Downloading & Decrypting {num_messages} Messages [{batch_name}] ---")

    received_logs = []
    valid_replies = []

    # State variables for the chain
    current_ks = None
    current_kdf_next = None
    last_session_id = None
    session_valid = False

    for i in range(num_messages):
        msg_data = ReqMsg(R_sig, s_sig)
        if not msg_data: break

        idB, otkID, msgID, msg_int, ik_x, ik_y, ek_x, ek_y, pqID, pqct = msg_data

        print(f"\nProcessing Message {msgID} from {idB}...")

        # Session identification
        session_id = (ek_x, ek_y, otkID, pqID)

        # --- NEW SESSION DETECTION ---
        if session_id != last_session_id:
            print("  -> Detected New Session Header (PQXDH)...")
            last_session_id = session_id
            session_valid = False

            if otkID not in OTKs:
                print(f"  Error: Missing OTK {otkID}.")
                Checker(idB, msgID, "DECRYPTION_FAILED")
                received_logs.append({'id': msgID, 'text': "Missing OTK", 'valid': False, 'batch': batch_name})
                continue

            if pqID is None or pqID not in PQOTKs:
                print(f"  Error: Missing/Invalid PQOTK {pqID}.")
                Checker(idB, msgID, "DECRYPTION_FAILED")
                received_logs.append({'id': msgID, 'text': "Missing PQOTK", 'valid': False, 'batch': batch_name})
                continue

            try:
                IK_B = Point(ik_x, ik_y, curve)
                EK_B = Point(ek_x, ek_y, curve)
                current_ks = PQXDH_Receiver(IK_B, EK_B, IK_Pri, SPK_Pri, OTKs[otkID]["pri"], PQOTKs[pqID]["sk"], pqct)
                current_kdf_next = current_ks
                session_valid = True
                print("  -> Session Established Successfully.")
            except Exception as e:
                print(f"  Error computing PQXDH: {e}")
                session_valid = False
                Checker(idB, msgID, "DECRYPTION_FAILED")
                continue

        # --- DECRYPTION ---
        if not session_valid or current_kdf_next is None:
            print("  -> Skipping message (Session invalid).")
            Checker(idB, msgID, "DECRYPTION_FAILED")
            received_logs.append({'id': msgID, 'text': "Skipped", 'valid': False, 'batch': batch_name})
            continue

        K_enc, K_hmac, K_next = KDF_Chain(current_kdf_next)
        current_kdf_next = K_next

        plaintext, is_valid = Decrypt_Message(msg_int, K_enc, K_hmac)
        print(f"  -> Decrypted: {plaintext}")

        if is_valid:
            valid_replies.append({'msgID': msgID, 'text': plaintext, 'senderID': idB})
            Checker(idB, msgID, plaintext)
        else:
            Checker(idB, msgID, "INVALIDHMAC")

        received_logs.append({'id': msgID, 'text': plaintext, 'valid': is_valid, 'batch': batch_name})

    return received_logs, valid_replies


# -----------------------------------------------------------------------------
# MAIN EXECUTION
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # --- STEP 1: KEY SETUP ---
    print("\n[STEP 1] Key Setup...")
    IK_Pri, IK_Pub, is_ik_reg = load_or_create_ik()
    id_bytes_dyn = to_bytes(stuID, length=None)

    if not is_ik_reg:
        R_IK, s_IK = SignGen(id_bytes_dyn, IK_Pri, IK_Pub)
        if IKRegReq(R_IK, s_IK, IK_Pub.x, IK_Pub.y):
            code = int(input("Enter verification code: "))
            if IKRegVerify(code):
                print("✓ IK Registered")
            else:
                sys.exit("IK Verification Failed")
        else:
            sys.exit("IK Registration Failed")

    SPK_Pri, SPK_Pub, is_spk_reg = load_or_create_spk()
    if not is_spk_reg:
        spk_bytes = to_bytes(SPK_Pub.x, 32) + to_bytes(SPK_Pub.y, 32)
        R_SPK, s_SPK = SignGen(spk_bytes, IK_Pri, IK_Pub)
        SPKReg(R_SPK, s_SPK, SPK_Pub.x, SPK_Pub.y)

    OTKs, is_otk_reg = load_or_create_otks()
    if not is_otk_reg:
        print("Registering 10 OTKs...")
        T = SPK_Pri * IKey_Ser
        U = b'TheHMACKeyToSuccess' + to_bytes(T.y, 32) + to_bytes(T.x, 32)
        K_HMAC = SHA3_256.new(U).digest()

        otk_buffer = {}
        for i in range(10):
            pri, pub = KeyGen(curve)
            hmac = HMAC.new(K_HMAC, to_bytes(pub.x, 32) + to_bytes(pub.y, 32), digestmod=SHA256).hexdigest()
            if OTKReg(i, pub.x, pub.y, hmac):
                otk_buffer[i] = {"pri": pri, "pub": pub}
            else:
                print(f"Warning: OTK {i} rejected by server.")

        OTKs = otk_buffer
        save_otks(OTKs)

    PQOTKs, is_pq_reg = load_or_create_pqotks()
    if not is_pq_reg:
        print("Registering 10 PQOTKs...")
        pq_buffer = {}
        for i in range(10):
            pk, sk = Kyber1024.keygen()
            print(f"\n{i}th PQ OTK generated.")
            print(f"Public key length: {len(pk)} bytes")
            print(f"Public key (hex): {pk.hex()[:60]}...")

            R_PQ, s_PQ = SignGen(pk, IK_Pri, IK_Pub)
            print(f"Signature: R=({R_PQ.x}, {R_PQ.y}), s={s_PQ}")

            if PQOTKReg(i, pk.hex(), R_PQ, s_PQ):
                pq_buffer[i] = {"pk": pk, "sk": sk}
            else:
                print(f"Warning: PQOTK {i} rejected by server.")
            print("\n+++++++++++++++++++++++++++++++++++++++++++++")

        PQOTKs = pq_buffer
        save_pqotks(PQOTKs)
    else:
        print("PQ OTKs already registered (loaded from file).")

    # --- STEP 2: CONFERENCE KEYING ---
    print("\n[STEP 2] Conference Keying...")
    r1, z1 = KeyGen(curve)
    z1_msg = to_bytes(z1.x, length=None) + to_bytes(z1.y, length=None)
    R_z1, s_z1 = SignGen(z1_msg, IK_Pri, IK_Pub)

    z2x, z2y, z4x, z4y = ExchangePartialKeys(z1.x, z1.y, R_z1, s_z1)
    if z2x:
        z2, z4 = Point(z2x, z2y, curve), Point(z4x, z4y, curve)
        z4_neg = Point((-z4.x) % field, z4.y, curve)
        x1 = r1 * (z2 + z4_neg)
        print(f"x1 computed: ({x1.x}, {x1.y})")

        x1_msg = to_bytes(x1.x, length=None) + to_bytes(x1.y, length=None)
        R_x1, s_x1 = SignGen(x1_msg, IK_Pri, IK_Pub)
        x2x, x2y, x3x, x3y, x4x, x4y = ExchangeXs(x1.x, x1.y, R_x1, s_x1)


        if x2x:
            x2, x3, x4 = Point(x2x, x2y, curve), Point(x3x, x3y, curve), Point(x4x, x4y, curve)
            K = 4 * (r1 * z2) + 3 * x2 + 2 * x3 + 1 * x4
            print(f"Conference Key K: ({K.x}, {K.y})")

            print("Verifying conference key with server...")
            BonusChecker(K.x, K.y)
            print("Conference key establishment complete!")

    # --- STEP 3: RECEIVE MESSAGES ---
    R_sig, s_sig = SignGen(id_bytes_dyn, IK_Pri, IK_Pub)
    all_logs = []
    all_replies = []

    # Phase A: Check Inbox
    print("\n[STEP 3A] Checking for existing mail...")
    st = Status(R_sig, s_sig)
    num_waiting = st.get('numMSG', 0) if st else 0
    if num_waiting > 0:
        print(f"Found {num_waiting} messages. Fetching...")
        l, r = fetch_and_decrypt(num_waiting, R_sig, s_sig, IK_Pri, SPK_Pri, OTKs, PQOTKs, "Inbox")
        all_logs.extend(l)
        all_replies.extend(r)
    else:
        print("Inbox is empty.")

    # Phase B: Trigger New
    print("\n[STEP 3B] Requesting NEW messages...")
    PseudoSendMsg(R_sig, s_sig)
    st = Status(R_sig, s_sig)
    num_new = st.get('numMSG', 0) if st else 0
    if num_new > 0:
        l, r = fetch_and_decrypt(num_new, R_sig, s_sig, IK_Pri, SPK_Pri, OTKs, PQOTKs, "Pseudo-Client")
        all_logs.extend(l)
        all_replies.extend(r)

    # Phase C: Check Deleted
    print("\n[STEP 3C] Checking for Deleted Messages...")
    deleted_ids = ReqDelMsgs(R_sig, s_sig)
    print(f"Deleted IDs: {deleted_ids}")

    # LOG DISPLAY
    print("\n" + "+" * 42)
    print("+          FULL MESSAGE LOG              +")
    print("+" * 42)
    curr_batch = None
    for m in all_logs:
        if m['batch'] != curr_batch:
            curr_batch = m['batch']
            print(f"\n--- BATCH: {curr_batch} ---")

        status_txt = "- Read"
        if not m['valid']:
            status_txt = "- Invalid MAC"
        elif m['id'] in deleted_ids:
            status_txt = "- Was deleted by sender - X"

        print(f"Message {m['id']} - {m['text'] if m['valid'] else 'N/A'} {status_txt}")
    print("\n" + "+" * 42)

    # --- STEP 4: SENDING MESSAGES ---
    print("\n[STEP 4] Sending Replies...")

    # Replying to any message received, sending the reply to configured stuIDB
    valid_msgs = [m for m in all_replies if m['msgID'] not in deleted_ids]

    if valid_msgs:
        target_id_val = stuIDB
        print(f"Preparing to send {len(valid_msgs)} replies to Target ID: {target_id_val}")
        target_id_bytes = to_bytes(target_id_val, length=None)
        R_tgt, s_tgt = SignGen(target_id_bytes, IK_Pri, IK_Pub)

        kb = ReqKeyBundle(target_id_val, R_tgt, s_tgt)
        if kb:
            # Verify Bundle
            kb_ik = Point(kb['IK.X'], kb['IK.Y'], curve)
            kb_spk = Point(kb['SPK.X'], kb['SPK.Y'], curve)
            kb_otk = Point(kb['OTK.X'], kb['OTK.Y'], curve)

            spk_d = to_bytes(kb['SPK.X'], length=None) + to_bytes(kb['SPK.Y'], length=None)
            if SignVer(spk_d, int(kb['SPK.S']), Point(kb['SPK.R.X'], kb['SPK.R.Y'], curve), kb_ik):
                print("✓ SPK Signature Verified")
            else:
                print("WARNING: SPK Sig Verification Failed!")

            EK_Pri, EK_Pub = KeyGen(curve)
            Ks_Send, pqct_hex = PQXDH_Sender(kb_ik, kb_spk, kb_otk, IK_Pri, EK_Pri, kb['PQPK'])
            kdf_send = Ks_Send

            for m in valid_msgs:
                K_enc, K_hmac, kdf_send = KDF_Chain(kdf_send)
                ct = Encrypt_Message(m['text'], K_enc, K_hmac)
                SendMsg(target_id_val, kb['KEYID'], m['msgID'], ct, EK_Pub, kb['PQKEYID'], pqct_hex)
        else:
            print("Could not get key bundle.")
    else:
        print("No valid messages to reply to.")

    # --- STEP 5: MAINTENANCE & REFILL ---
    print("\n[STEP 5] Maintenance & Key Refill...")

    # Check Status
    st = Status(R_sig, s_sig)
    if st:
        # A. Refill OTKs
        num_otk = st.get('numOTK', 0)
        if num_otk < 10:
            needed = 10 - num_otk
            print(f"OTKs low ({num_otk}/10). Generating {needed} new OTKs...")

            # Re-calculate K_HMAC for registration
            T = SPK_Pri * IKey_Ser
            U = b'TheHMACKeyToSuccess' + to_bytes(T.y, 32) + to_bytes(T.x, 32)
            K_HMAC = SHA3_256.new(U).digest()

            # Find next ID
            current_ids = sorted([k for k in OTKs.keys()])
            next_id = (current_ids[-1] + 1) if current_ids else 0

            for i in range(needed):
                new_id = next_id + i
                pri, pub = KeyGen(curve)
                hmac = HMAC.new(K_HMAC, to_bytes(pub.x, 32) + to_bytes(pub.y, 32), digestmod=SHA256).hexdigest()

                if OTKReg(new_id, pub.x, pub.y, hmac):
                    OTKs[new_id] = {"pri": pri, "pub": pub}
                    print(f"  Registered OTK {new_id}")
                else:
                    print(f"  Failed OTK {new_id}")
            save_otks(OTKs)
        else:
            print(f"OTK count sufficient ({num_otk}/10).")

        # B. Refill PQOTKs
        num_pq = st.get('numPQOTK', 0)
        if num_pq < 10:
            needed = 10 - num_pq
            print(f"PQOTKs low ({num_pq}/10). Generating {needed} new PQOTKs...")

            # Find next ID
            current_ids = sorted([k for k in PQOTKs.keys()])
            next_id = (current_ids[-1] + 1) if current_ids else 0

            for i in range(needed):
                new_id = next_id + i
                pk, sk = Kyber1024.keygen()
                # Sign PQPK (Raw bytes)
                R_pq, s_pq = SignGen(pk, IK_Pri, IK_Pub)

                if PQOTKReg(new_id, pk.hex(), R_pq, s_pq):
                    PQOTKs[new_id] = {"pk": pk, "sk": sk}
                    print(f"  Registered PQOTK {new_id}")
                else:
                    print(f"  Failed PQOTK {new_id}")
            save_pqotks(PQOTKs)
        else:
            print(f"PQOTK count sufficient ({num_pq}/10).")

    # Cleanup Prompt
    if input("\nDelete Local Keys (Factory Reset)? (y/n): ").lower() == 'y':
        print("Deleting keys from Server & Local...")
        print("Deleting OTKs...")
        ResetOTK(R_sig, s_sig)
        print("OTKs Deleted.")

        print("Deleting SPK...")
        ResetSPK(R_sig, s_sig)
        print("SPK Deleted.")

        rcode = input("Enter RCODE (from email) to delete IK, or press Enter to skip: ")
        if rcode:
            print("Deleting Identity Key...")
            ResetIK(int(rcode))
            print("Identity Key Deleted.")

        for f in [IK_FILE, SPK_FILE, OTK_FILE, PQOTK_FILE]:
            if os.path.exists(f):
                os.remove(f)
                print(f"Removed local file: {f}")
        print("Cleanup Complete.")