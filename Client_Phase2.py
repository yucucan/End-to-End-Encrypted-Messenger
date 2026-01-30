import math
import time
import random
import sys
import json
import os
import warnings
import requests

# Cryptography Imports
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_512, SHA3_256, SHA256, HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import random as crypto_random
from Crypto.Util import number

# -----------------------------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------------------------

API_URL = 'http://harpoon1.sabanciuniv.edu:9999'
stuID = 34218
stuIDB = 18007 # 34245 18007 34335 34401
IK_FILE = "IdentityKey.json"
SPK_FILE = "SignedPreKey.json"
OTK_FILE = "OneTimeKeys.json"

# Curve Setup: Ed25519
curve = Curve.get_curve('Ed25519')
n = curve.order
P = curve.generator

# Server's Identity Public Key
IKey_Ser_X_Hex = "0x2eef2e2656fb3d8c3c4932c679fbca121c2ea5fe26deecd800bc9311ef06f06"
IKey_Ser_Y_Hex = "0x17a8a7f452068d1157a974abc69cd5ae83d528936b4c1d8dab6095d28eeedcc0"
IKey_Ser = Point(int(IKey_Ser_X_Hex, 16), int(IKey_Ser_Y_Hex, 16), curve)


# -----------------------------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------------------------

def to_bytes(val, length=32):
    if length is None:
        if val == 0:
            return b'\x00'
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
    buff = to_bytes(R.x) + to_bytes(R.y) + to_bytes(QA.x) + to_bytes(QA.y) + message_bytes
    h2_digest = SHA3_512.new(buff).digest()
    h2_int = int.from_bytes(h2_digest, 'big') % n
    s = (r_int + (sA * h2_int)) % n
    return R, s


def SignVer(message_bytes, s, R, QA):
    """
    Verifies a signature.
    UPDATED: Uses length=None to match Pseudo-Client's dynamic byte encoding.
    """
    buff = (to_bytes(R.x, length=None) +
            to_bytes(R.y, length=None) +
            to_bytes(QA.x, length=None) +
            to_bytes(QA.y, length=None) +
            message_bytes)

    h2_digest = SHA3_512.new(buff).digest()
    h2_int = int.from_bytes(h2_digest, 'big') % n
    v1 = s * P
    v2 = R + (h2_int * QA)
    return v1 == v2


# -----------------------------------------------------------------------------
# FILE LOADING
# -----------------------------------------------------------------------------

def load_ik():
    if not os.path.exists(IK_FILE):
        raise FileNotFoundError("Identity Key file not found. Run Phase 1 first.")
    with open(IK_FILE, "r") as f:
        data = json.load(f)
        pri = int(data["pri_key"])
        pub = pri * P
        return pri, pub


def load_spk():
    if not os.path.exists(SPK_FILE):
        raise FileNotFoundError("SPK file not found. Run Phase 1 first.")
    with open(SPK_FILE, "r") as f:
        data = json.load(f)
        pri = int(data["pri_key"])
        pub = pri * P
        return pri, pub


def load_otks():
    if not os.path.exists(OTK_FILE):
        raise FileNotFoundError("OTK file not found. Run Phase 1 first.")
    with open(OTK_FILE, "r") as f:
        data = json.load(f)
        otk_dict = {}
        for k, v in data.items():
            pri = int(v["pri_key"])
            otk_dict[int(k)] = {"pri": pri, "pub": pri * P}
        return otk_dict


# -----------------------------------------------------------------------------
# API WRAPPERS
# -----------------------------------------------------------------------------

def PseudoSendMsg(R, s):
    mes = {'ID': stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    print("Requesting pseudo-client messages...")
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json=mes)
    print("Server Response:", response.json())
    return response.ok


def ReqMsg(R, s):
    mes = {'ID': stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json=mes)
    if response.ok:
        res = response.json()
        return (res["IDB"], res["OTKID"], res["MSGID"], int(res["MSG"]),
                int(res["IK.X"]), int(res["IK.Y"]), int(res["EK.X"]), int(res["EK.Y"]))
    else:
        print("ReqMsg Failed:", response.json())
        return None


def ReqDelMsgs(R, s):
    mes = {'ID': stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    print("Checking for deleted messages...")
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json=mes)
    if response.ok:
        return response.json().get("MSGID", [])
    return []


def Checker(stuIDB, msgID, decmsg):
    mes = {'IDA': stuID, 'IDB': stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print(f"Sending verification for Message {msgID}...")
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json=mes)
    print("Checker Response:", response.json())


def ReqKeyBundle(target_id, R, s):
    mes = {'IDA': stuID, 'IDB': target_id, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    print(f"Requesting Key Bundle for User {target_id}...")
    response = requests.get('{}/{}'.format(API_URL, "ReqKeyBundle"), json=mes)
    if response.ok:
        return response.json()
    else:
        print("ReqKeyBundle Failed:", response.json())
        return None


def SendMsg(idB, otkid, msgid, msg, ek):
    _, IK_Pub = load_ik()
    mes = {
        "IDA": stuID,
        "IDB": idB,
        "OTKID": int(otkid),
        "MSGID": msgid,
        "MSG": msg,
        "IK.X": IK_Pub.x,
        "IK.Y": IK_Pub.y,
        "EK.X": ek.x,
        "EK.Y": ek.y
    }
    print(f"Sending Message {msgid} to {idB}...")
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json=mes)
    print("SendMsg Response:", response.json())


def Status(R, s):
    mes = {'ID': stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    if response.ok:
        return response.json()
    return None


def OTKReg(keyID, x, y, hmac_val):
    mes = {'ID': stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac_val}
    requests.put('{}/{}'.format(API_URL, "OTKReg"), json=mes)


# -----------------------------------------------------------------------------
# CORE PROTOCOL IMPLEMENTATION
# -----------------------------------------------------------------------------

def X3DH_Receiver(IK_B, EK_B, IK_A_Pri, SPK_A_Pri, OTK_A_Pri):
    T1 = SPK_A_Pri * IK_B
    T2 = IK_A_Pri * EK_B
    T3 = SPK_A_Pri * EK_B
    T4 = OTK_A_Pri * EK_B

    U = (to_bytes(T1.x) + to_bytes(T1.y) +
         to_bytes(T2.x) + to_bytes(T2.y) +
         to_bytes(T3.x) + to_bytes(T3.y) +
         to_bytes(T4.x) + to_bytes(T4.y) +
         b'WhatsUpDoc')

    return SHA3_256.new(U).digest()


def X3DH_Sender(IK_B, SPK_B, OTK_B, IK_A_Pri, EK_A_Pri):
    T1 = IK_A_Pri * SPK_B
    T2 = EK_A_Pri * IK_B
    T3 = EK_A_Pri * SPK_B
    T4 = EK_A_Pri * OTK_B

    U = (to_bytes(T1.x) + to_bytes(T1.y) +
         to_bytes(T2.x) + to_bytes(T2.y) +
         to_bytes(T3.x) + to_bytes(T3.y) +
         to_bytes(T4.x) + to_bytes(T4.y) +
         b'WhatsUpDoc')

    return SHA3_256.new(U).digest()


def KDF_Chain(K_root):
    buff_enc = K_root + b'JustKeepSwimming'
    K_enc = SHA3_256.new(buff_enc).digest()

    buff_hmac = K_root + K_enc + b'HakunaMatata'
    K_hmac = SHA3_256.new(buff_hmac).digest()

    buff_next = K_enc + K_hmac + b'OhanaMeansFamily'
    K_next = SHA3_256.new(buff_next).digest()

    return K_enc, K_hmac, K_next


def Decrypt_Message(msg_int, K_enc, K_hmac):
    """
    Decrypts using SAFE integer-to-byte conversion (Hex).
    """
    msg_hex = hex(msg_int)[2:]
    if len(msg_hex) % 2 != 0:
        msg_hex = '0' + msg_hex

    try:
        msg_bytes = bytes.fromhex(msg_hex)
    except ValueError:
        return "INVALID_ENCODING", False

    if len(msg_bytes) < 41:
        return "INVALIDHMAC", False

    nonce = msg_bytes[:8]
    mac_received = msg_bytes[-32:]
    ciphertext = msg_bytes[8:-32]

    hmac_calc = HMAC.new(K_hmac, ciphertext, digestmod=SHA256).digest()

    if hmac_calc != mac_received:
        return "INVALIDHMAC", False

    cipher = AES.new(K_enc, AES.MODE_CTR, nonce=nonce)
    try:
        plaintext_bytes = cipher.decrypt(ciphertext)
        plaintext = plaintext_bytes.decode('utf-8')
        return plaintext, True
    except Exception as e:
        return "DECRYPTION_FAILED", False


def Encrypt_Message(plaintext_str, K_enc, K_hmac):
    cipher = AES.new(K_enc, AES.MODE_CTR)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(plaintext_str.encode('utf-8'))
    hmac_val = HMAC.new(K_hmac, ciphertext, digestmod=SHA256).digest()
    final_bytes = nonce + ciphertext + hmac_val
    return int.from_bytes(final_bytes, 'big')


# -----------------------------------------------------------------------------
# REFACTORED FETCH FUNCTION
# -----------------------------------------------------------------------------

def fetch_and_decrypt(num_messages, R_sig, s_sig, IK_Pri, SPK_Pri, OTKs, batch_name="Unknown"):
    print(f"\n--- Downloading & Decrypting {num_messages} Messages [{batch_name}] ---")

    received_logs = []
    valid_replies = []

    current_ks = None
    current_kdf_next = None
    last_ek_coords = None
    last_otk_id = None

    for i in range(num_messages):
        msg_data = ReqMsg(R_sig, s_sig)
        if not msg_data:
            print("  -> ReqMsg returned no data.")
            break

        idB, otkID, msgID, msg_int, ik_x, ik_y, ek_x, ek_y = msg_data

        print(f"\nProcessing Message {msgID} from {idB}...")

        EK_B = Point(ek_x, ek_y, curve)
        IK_B = Point(ik_x, ik_y, curve)

        is_new_chain = False
        if (last_ek_coords != (ek_x, ek_y)) or (last_otk_id != otkID) or (current_ks is None):
            is_new_chain = True
            last_ek_coords = (ek_x, ek_y)
            last_otk_id = otkID

        if is_new_chain:
            print("  -> Starting new Session (X3DH)...")
            if otkID not in OTKs:
                print(f"  Error: OTK ID {otkID} not found in local storage!")
                received_logs.append({'id': msgID, 'text': "OTK Missing", 'valid': False, 'batch': batch_name})
                continue

            my_otk_pri = OTKs[otkID]["pri"]
            current_ks = X3DH_Receiver(IK_B, EK_B, IK_Pri, SPK_Pri, my_otk_pri)
            current_kdf_next = current_ks

        K_enc, K_hmac, K_next = KDF_Chain(current_kdf_next)
        current_kdf_next = K_next

        plaintext, is_valid = Decrypt_Message(msg_int, K_enc, K_hmac)

        print(f"  -> Decrypted: {plaintext}")
        if is_valid:
            print("  -> MAC Verified.")
            valid_replies.append({'msgID': msgID, 'text': plaintext, 'senderID': idB})
        else:
            print("  -> MAC INVALID!")

        Checker(idB, msgID, plaintext)
        received_logs.append({'id': msgID, 'text': plaintext, 'valid': is_valid, 'batch': batch_name})

    return received_logs, valid_replies


# -----------------------------------------------------------------------------
# MAIN EXECUTION
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # 1. Load Keys
    try:
        IK_Pri, IK_Pub = load_ik()
        SPK_Pri, SPK_Pub = load_spk()
        OTKs = load_otks()
        print("Keys loaded successfully.")
    except Exception as e:
        print(f"Critical Error: {e}")
        sys.exit(1)

    # 2. Generate Signature for Requests
    id_bytes = to_bytes(stuID, length=(stuID.bit_length() + 7) // 8)
    R_sig, s_sig = SignGen(id_bytes, IK_Pri, IK_Pub)

    all_received_logs = []
    all_valid_replies = []

    # PHASE A: CHECK AND CLEAR EXISTING MAIL
    print("\n[PHASE A] Checking for existing mail...")
    status_info = Status(R_sig, s_sig)
    num_waiting = status_info.get('numMSG', 0) if status_info else 0

    if num_waiting > 0:
        print(f"Found {num_waiting} messages waiting. Clearing them now...")
        logs, replies = fetch_and_decrypt(num_waiting, R_sig, s_sig, IK_Pri, SPK_Pri, OTKs,
                                          batch_name="Inbox (Existing)")
        all_received_logs.extend(logs)
        all_valid_replies.extend(replies)
    else:
        print("Inbox is empty.")

    print("\n++++++++++++++++++++++++++++++++++++++++++")
    print("  --- TRANSITIONING TO NEW MESSAGES ---")
    print("++++++++++++++++++++++++++++++++++++++++++\n")

    # PHASE B: TRIGGER PSEUDO-CLIENT & FETCH NEW MAIL
    print("[PHASE B] Requesting NEW messages from Pseudo-Client...")
    PseudoSendMsg(R_sig, s_sig)

    status_info = Status(R_sig, s_sig)
    num_new = status_info.get('numMSG', 0) if status_info else 0
    print(f"Pseudo-Client sent {num_new} messages.")

    if num_new > 0:
        logs, replies = fetch_and_decrypt(num_new, R_sig, s_sig, IK_Pri, SPK_Pri, OTKs,
                                          batch_name="Pseudo-Client (New)")
        all_received_logs.extend(logs)
        all_valid_replies.extend(replies)

    # PHASE C: CHECK DELETED & DISPLAY LOG
    print("\n[PHASE C] Checking for Deleted Messages...")
    deleted_ids = ReqDelMsgs(R_sig, s_sig)
    print(f"Deleted Message IDs: {deleted_ids}")

    print("\n++++++++++++++++++++++++++++++++++++++++++")
    print("+          FULL MESSAGE LOG              +")
    print("++++++++++++++++++++++++++++++++++++++++++")

    current_batch = None
    for m in all_received_logs:
        if m['batch'] != current_batch:
            current_batch = m['batch']
            print(f"\n--- BATCH: {current_batch} ---")

        status = ""
        if not m['valid']:
            status = "- Invalid MAC"
        elif m['id'] in deleted_ids:
            status = "- Was deleted by sender - X"
        else:
            status = "- Read"
        display_text = m['text'] if m['valid'] else "N/A"
        print(f"Message {m['id']} - {display_text} {status}")
    print("\n++++++++++++++++++++++++++++++++++++++++++\n")

    # PHASE D: REPLY
    print("[PHASE D] Replying to valid messages...")

    messages_to_send = [m for m in all_valid_replies if m['msgID'] not in deleted_ids]

    if not messages_to_send:
        print("No valid messages to reply to.")
    else:
        for msg_info in messages_to_send:
            target_id = stuIDB # msg_info['senderID']
            msg_id = msg_info['msgID']
            text = msg_info['text']

            target_id_bytes = to_bytes(target_id, length=(target_id.bit_length() + 7) // 8)
            R_target, s_target = SignGen(target_id_bytes, IK_Pri, IK_Pub)

            kb = ReqKeyBundle(target_id, R_target, s_target)
            if not kb:
                print(f"Failed to get Key Bundle for User {target_id}. Skipping.")
                continue

            kb_keyid = kb['KEYID']
            kb_ik = Point(kb['IK.X'], kb['IK.Y'], curve)
            kb_spk = Point(kb['SPK.X'], kb['SPK.Y'], curve)
            kb_otk = Point(kb['OTK.X'], kb['OTK.Y'], curve)

            # --- KEY FIX FOR WARNING ---
            # Use dynamic length (length=None) for SPK data verification
            spk_data = to_bytes(kb['SPK.X'], length=None) + to_bytes(kb['SPK.Y'], length=None)
            spk_R = Point(kb['SPK.R.X'], kb['SPK.R.Y'], curve)
            spk_s = int(kb['SPK.S'])

            if SignVer(spk_data, spk_s, spk_R, kb_ik):
                print(f"Target SPK Verified (Signed by User {target_id}).")
            elif SignVer(spk_data, spk_s, spk_R, IKey_Ser):
                print(f"Target SPK Verified (Signed by Server).")
            else:
                print(f"WARNING: SPK Verification failed for {target_id}. Sending anyway...")

            EK_A_Pri, EK_A_Pub = KeyGen(curve)
            Ks_Sender = X3DH_Sender(kb_ik, kb_spk, kb_otk, IK_Pri, EK_A_Pri)

            K_enc, K_hmac, K_next = KDF_Chain(Ks_Sender)
            msg_int = Encrypt_Message(text, K_enc, K_hmac)

            SendMsg(target_id, kb_keyid, msg_id, msg_int, EK_A_Pub)

    # PHASE E: OTK REFILL
    print("\n[PHASE E] Status Check & OTK Refill...")
    status = Status(R_sig, s_sig)
    if status:
        print(f"Status: {status}")
        num_otk = status.get('numOTK', 10)

        if num_otk < 10:
            needed = 10 - num_otk
            print(f"Need to register {needed} new OTKs.")

            current_ids = sorted(OTKs.keys())
            next_id = current_ids[-1] + 1 if current_ids else 0

            T_hmac = SPK_Pri * IKey_Ser
            U_hmac = b'TheHMACKeyToSuccess' + to_bytes(T_hmac.y) + to_bytes(T_hmac.x)
            K_Reg_HMAC = SHA3_256.new(U_hmac).digest()

            for i in range(needed):
                new_id = next_id + i
                new_pri, new_pub = KeyGen(curve)

                otk_bytes = to_bytes(new_pub.x) + to_bytes(new_pub.y)
                hmac_val = HMAC.new(K_Reg_HMAC, otk_bytes, digestmod=SHA256).hexdigest()

                OTKReg(new_id, new_pub.x, new_pub.y, hmac_val)
                OTKs[new_id] = {"pri": new_pri, "pub": new_pub}
                print(f"Registered OTK ID {new_id}")

            serializable_otks = {}
            for k, v in OTKs.items():
                serializable_otks[k] = {
                    "pri_key": str(v["pri"]),
                    "pub_x": str(v["pub"].x),
                    "pub_y": str(v["pub"].y)
                }
            with open(OTK_FILE, "w") as f:
                json.dump(serializable_otks, f, indent=4)
            print("OTKs updated and saved.")
        else:
            print("OTK count is sufficient.")
