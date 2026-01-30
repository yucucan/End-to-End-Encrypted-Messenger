import math
import time
import random
import sys
import json
import os
import warnings

import requests
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_512, SHA3_256, SHA256, HMAC
from Crypto.Random import random as crypto_random

# -----------------------------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------------------------

API_URL = 'http://harpoon1.sabanciuniv.edu:9999'
stuID = 34218
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

# CRYPTOGRAPHIC HELPER FUNCTIONS
def to_bytes(val, length=32):
    """Converts an integer to bytes (Big Endian)."""
    if length is None:
        length = (val.bit_length() + 7) // 8
    return val.to_bytes(length, byteorder='big')


def KeyGen(curve):
    """Generates a Private (int) and Public (Point) Key Pair."""
    sA = crypto_random.randint(1, n - 2)
    QA = sA * P
    return sA, QA


def SignGen(message_bytes, sA, QA):
    """Generates a signature (R, s) for a message."""
    h1 = SHA3_512.new(to_bytes(sA, 32)).digest()
    r_digest = SHA3_512.new(h1[32:] + message_bytes).digest()
    r_int = int.from_bytes(r_digest, 'big') % n
    R = r_int * P
    buff = to_bytes(R.x) + to_bytes(R.y) + to_bytes(QA.x) + to_bytes(QA.y) + message_bytes
    h2_digest = SHA3_512.new(buff).digest()
    h2_int = int.from_bytes(h2_digest, 'big') % n
    s = (r_int + (sA * h2_int)) % n
    return R, s


# FILE OPERATIONS (SAVING & LOADING)
def load_or_create_ik():
    """Checks/Loads Identity Key. Returns (Pri, Pub, is_registered_flag)."""
    if os.path.exists(IK_FILE):
        print(f"Found existing key file: {IK_FILE}")
        try:
            with open(IK_FILE, "r") as f:
                data = json.load(f)
                pri = int(data["pri_key"])
                pub = pri * P
                print("Identity Key loaded from file.")
                return pri, pub, True
        except Exception as e:
            print(f"Error loading IK: {e}. Generating new one.")

    print("Creating new Identity Key.")
    pri, pub = KeyGen(curve)
    with open(IK_FILE, "w") as f:
        json.dump({"pri_key": str(pri), "pub_x": str(pub.x), "pub_y": str(pub.y)}, f, indent=4)
    print(f"Saved new Identity Key to {IK_FILE}")
    return pri, pub, False


def load_or_create_spk():
    """Checks/Loads SPK. Returns (Pri, Pub, is_registered_flag)."""
    if os.path.exists(SPK_FILE):
        print(f"Found existing key file: {SPK_FILE}")
        try:
            with open(SPK_FILE, "r") as f:
                data = json.load(f)
                pri = int(data["pri_key"])
                pub = pri * P
                print("Signed Pre-Key loaded from file.")
                return pri, pub, True
        except Exception as e:
            print(f"Error loading SPK: {e}. Generating new one.")

    print("Generating new SPK...")
    pri, pub = KeyGen(curve)

    # Save
    data = {"pri_key": str(pri), "pub_x": str(pub.x), "pub_y": str(pub.y)}
    with open(SPK_FILE, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Saved SPK to {SPK_FILE}")
    return pri, pub, False


def load_or_create_otks():
    """Checks/Loads OTKs. Returns (Dict {id: {'pri':..., 'pub':...}}, is_registered_flag)."""
    if os.path.exists(OTK_FILE):
        print(f"Found existing key file: {OTK_FILE}")
        try:
            with open(OTK_FILE, "r") as f:
                data = json.load(f)
                otk_dict = {}
                for k, v in data.items():
                    pri = int(v["pri_key"])
                    otk_dict[int(k)] = {"pri": pri, "pub": pri * P}
                print("One-Time Keys loaded from file.")
                return otk_dict, True
        except Exception as e:
            print(f"Error loading OTKs: {e}. Generating new ones.")

    return {}, False


def save_otks(otk_dict):
    """Saves dictionary of OTKs to JSON."""
    serializable_otks = {}
    for key_id, keys in otk_dict.items():
        serializable_otks[key_id] = {
            "pri_key": str(keys["pri"]),
            "pub_x": str(keys["pub"].x),
            "pub_y": str(keys["pub"].y)
        }
    with open(OTK_FILE, "w") as f:
        json.dump(serializable_otks, f, indent=4)
    print(f"Saved {len(otk_dict)} OTKs to {OTK_FILE}")


# API COMMUNICATION FUNCTIONS
def IKRegReq(R, s, x, y):
    mes = {'ID': stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json=mes)
    if not response.ok:
        print("Error:", response.json())
        sys.exit(1)


def IKRegVerify(code):
    mes = {'ID': stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json=mes)
    print(response.json())
    if not response.ok:
        print("Verification failed.")
        sys.exit(1)


def SPKReg(R, s, x, y):
    mes = {'ID': stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json=mes)
    if not response.ok:
        print("Error:", response.json())
    print(response.json())


def OTKReg(keyID, x, y, hmac_val):
    mes = {'ID': stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac_val}
    print("Sending message is: ", mes)
    requests.put('{}/{}'.format(API_URL, "OTKReg"), json=mes)


# DELETION FUNCTIONS
def ResetOTK(R, s):
    mes = {'ID': stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json=mes)
    print(response.json())


def ResetSPK(R, s):
    mes = {'ID': stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json=mes)
    print(response.json())


def ResetIK(rcode):
    mes = {'ID': stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json=mes)
    print(response.json())

# -----------------------------------------------------------------------------
# MAIN EXECUTION
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # =========================================================================
    # 2.1 Identity Key (IK) Handling
    # =========================================================================

    IK_Pri, IK_Pub, is_ik_registered = load_or_create_ik()
    id_bytes = to_bytes(stuID, length=(stuID.bit_length() + 7) // 8)

    if not is_ik_registered:
        print(f"My Private IKey: {IK_Pri}")
        print(f"My ID number is {stuID}")
        print(f"Converted my ID to bytes: {id_bytes}")
        print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")
        R_IK, s_IK = SignGen(id_bytes, IK_Pri, IK_Pub)
        print(f"Signature of my ID number is:\nR= (0x{R_IK.x:x} , 0x{R_IK.y:x}) \ns= {s_IK}")
        print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")
        print("Sending signature and my IKEY to server...")
        IKRegReq(R_IK, s_IK, IK_Pub.x, IK_Pub.y)
        print("Received the verification code through email")
        print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")
        code_input = int(input("Enter verification code: "))
        IKRegVerify(code_input)
        print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")
    else:
        print("Skipping IK Registration (Already registered locally).")
        print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

    # =========================================================================
    # 2.2 Signed Pre-key (SPK)
    # =========================================================================

    SPK_Pri, SPK_Pub, is_spk_registered = load_or_create_spk()

    if not is_spk_registered:
        print(f"Private SPK: {SPK_Pri}")
        print(f"Public SPK.x: {SPK_Pub.x}")
        print(f"Public SPK.y: {SPK_Pub.y}")
        print("Convert SPK.x and SPK.y to bytes in order to sign them...")

        spk_msg_bytes = to_bytes(SPK_Pub.x) + to_bytes(SPK_Pub.y)
        print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")
        print(f"Result: {spk_msg_bytes[:10]}...")

        # Sign with IK
        R_SPK, s_SPK = SignGen(spk_msg_bytes, IK_Pri, IK_Pub)

        print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")
        print(f"Signature of SPK is:\nR= (0x{R_SPK.x:x} , 0x{R_SPK.y:x}) \ns= {s_SPK}")
        print("Sending SPK and the signatures to the server...")
        print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")
        SPKReg(R_SPK, s_SPK, SPK_Pub.x, SPK_Pub.y)
        print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")
    else:
        print("Skipping SPK Registration (Already registered locally).")
        print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

    # =========================================================================
    # 2.3 One-Time Keys (OTK)
    # =========================================================================

    otk_storage, is_otk_registered = load_or_create_otks()

    if not is_otk_registered:
        print("Creating HMAC key (Diffie Hellman)")
        T = SPK_Pri * IKey_Ser
        print(f"T is (0x{T.x:x} , 0x{T.y:x})")
        U = b'TheHMACKeyToSuccess' + to_bytes(T.y) + to_bytes(T.x)
        print(f"U is {U}")
        K_HMAC = SHA3_256.new(U).digest()
        print(f"HMAC key is created {K_HMAC}")

        print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")
        print("Creating OTKs starting from index 0...")

        otk_storage = {}

        for i in range(10):
            print(f"{i}th key generated.")
            OTK_Pri, OTK_Pub = KeyGen(curve)
            otk_storage[i] = {"pri": OTK_Pri, "pub": OTK_Pub}

            print(f"Private part={OTK_Pri}")
            print(f"Public x={OTK_Pub.x}")
            print(f"Public y={OTK_Pub.y}")

            otk_msg_bytes = to_bytes(OTK_Pub.x) + to_bytes(OTK_Pub.y)
            print(f"Message {otk_msg_bytes[:20]}...")

            hmac_val = HMAC.new(K_HMAC, otk_msg_bytes, digestmod=SHA256).hexdigest()
            print(f"HMAC: \n{hmac_val}")

            OTKReg(i, OTK_Pub.x, OTK_Pub.y, hmac_val)
            print(f"OTK {i} registered successfully")
            print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

        save_otks(otk_storage)
        print("Key memory is full. There are 10 keys registered.")
        print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")
        print("OTK keys were generated successfully!")
        print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")
    else:
        print("Skipping OTK Registration (Already registered locally).")
        print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

    # =========================================================================
    # DELETION / RESET
    # =========================================================================

    confirm = input("Do you want to run the DELETION (RESET) protocol now? (y/n): ")
    if confirm.lower() == 'y':
        # Prepare Signature for Deletion (Signed ID)
        R_Del, s_Del = SignGen(id_bytes, IK_Pri, IK_Pub)

        # 1. Delete OTKs
        print("Trying to delete OTKs...")
        ResetOTK(R_Del, s_Del)
        if os.path.exists(OTK_FILE):
            os.remove(OTK_FILE)
            print("Local OTK file deleted.")
        print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

        # 2. Wrong Signature Test
        print("Trying to delete OTKs but sending wrong signatures...")
        ResetOTK(R_Del, s_Del + 1)
        print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

        # 3. Delete SPK
        print("Trying to delete SPK...")
        ResetSPK(R_Del, s_Del)
        if os.path.exists(SPK_FILE):
            os.remove(SPK_FILE)
            print("Local SPK file deleted.")
        print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

        # 4. Delete IK
        print("Trying to delete Identity Key...")
        print("WARNING: This will remove your key from the server.")
        rcode_input = input("Enter RCODE from email (or press Enter to skip): ")
        if rcode_input:
            ResetIK(int(rcode_input))
            if os.path.exists(IK_FILE):
                os.remove(IK_FILE)
                print("Local Identity Key file deleted.")
    else:
        print("Skipping deletion. Keys preserved for next run.")