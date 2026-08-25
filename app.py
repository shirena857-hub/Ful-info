import asyncio
import time
import httpx
import json
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64
import logging

# === Settings ===

MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB54"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}

# === Flask App Setup ===

app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)
uid_region_cache = {}

# === Helper Functions ===

def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def unpad(text: bytes) -> bytes:
    padding_length = text[-1]
    return text[:-padding_length]

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted = aes.decrypt(ciphertext)
    return unpad(decrypted)

def decode_protobuf(encoded_data: bytes, message_type: type) -> Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "IND":
        return "uid=4623975582&password=CZY-CGHBTTVNH-NEXU"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=4623973764&password=CZY-RRHQYX5A8-NEXU"
    else:
        return "uid=6549243316&password=Shihabkaksk_B44XB_xSaeed_EG9U1"

# === Token Generation (Async) ===

async def _get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = await _get_access_token(account)
    body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    url = "https://loginbp.ggpolarbear.com/MajorLogin"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
               'Content-Type': "application/octet-stream", 'Expect': "100-continue", 'X-Unity-Version': "2018.4.11f1",
               'X-GA': "v1 1", 'ReleaseVersion': RELEASEVERSION}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, data=payload, headers=headers)
        if resp.status_code != 200:
            raise Exception(f"Login request failed with status {resp.status_code}: {resp.text[:200]}")
        raw = resp.content
        try:
            login_res = decode_protobuf(raw, FreeFire_pb2.LoginRes)
        except Exception as e:
            if len(raw) % 16 == 0:
                try:
                    decrypted = aes_cbc_decrypt(MAIN_KEY, MAIN_IV, raw)
                    login_res = decode_protobuf(decrypted, FreeFire_pb2.LoginRes)
                except Exception as e2:
                    logging.error(f"Decryption failed: {e2}")
                    raise e2
            else:
                logging.error(f"Direct parsing failed and data not padded: {raw[:100]}")
                raise e
        msg = json.loads(json_format.MessageToJson(login_res))
        cached_tokens[region] = {
            'token': f"Bearer {msg.get('token','0')}",
            'region': msg.get('lockRegion','0'),
            'server_url': msg.get('serverUrl','0'),
            'expires_at': time.time() + 25200
        }

async def initialize_tokens():
    tasks = [create_jwt(r) for r in SUPPORTED_REGIONS]
    await asyncio.gather(*tasks)

async def get_token_info(region: str) -> Tuple[str, str, str]:
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    await create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

# === Core API Call ===

async def GetAccountInformation(uid, unk, region, endpoint):
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info(region)
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
               'Content-Type': "application/octet-stream", 'Expect': "100-continue",
               'Authorization': token, 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
               'ReleaseVersion': RELEASEVERSION}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(server + endpoint, data=data_enc, headers=headers)
        decoded = decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
        return json.loads(json_format.MessageToJson(decoded))

# === Formatter for /get endpoint ===

def format_response(data):
    return {
        "AccountInfo": {
            "AccountAvatarId": data.get("basicInfo", {}).get("headPic"),
            "AccountBPBadges": data.get("basicInfo", {}).get("badgeCnt"),
            "AccountBPID": data.get("basicInfo", {}).get("badgeId"),
            "AccountBannerId": data.get("basicInfo", {}).get("bannerId"),
            "AccountCreateTime": data.get("basicInfo", {}).get("createAt"),
            "AccountEXP": data.get("basicInfo", {}).get("exp"),
            "AccountLastLogin": data.get("basicInfo", {}).get("lastLoginAt"),
            "AccountLevel": data.get("basicInfo", {}).get("level"),
            "AccountLikes": data.get("basicInfo", {}).get("liked"),
            "AccountName": data.get("basicInfo", {}).get("nickname"),
            "AccountRegion": data.get("basicInfo", {}).get("region"),
            "AccountSeasonId": data.get("basicInfo", {}).get("seasonId"),
            "AccountType": data.get("basicInfo", {}).get("accountType"),
            "BrMaxRank": data.get("basicInfo", {}).get("maxRank"),
            "BrRankPoint": data.get("basicInfo", {}).get("rankingPoints"),
            "CsMaxRank": data.get("basicInfo", {}).get("csMaxRank"),
            "CsRankPoint": data.get("basicInfo", {}).get("csRankingPoints"),
            "EquippedWeapon": data.get("basicInfo", {}).get("weaponSkinShows", []),
            "ReleaseVersion": data.get("basicInfo", {}).get("releaseVersion"),
            "ShowBrRank": data.get("basicInfo", {}).get("showBrRank"),
            "ShowCsRank": data.get("basicInfo", {}).get("showCsRank"),
            "Title": data.get("basicInfo", {}).get("title")
        },
        "AccountProfileInfo": {
            "EquippedOutfit": data.get("profileInfo", {}).get("clothes", []),
            "EquippedSkills": data.get("profileInfo", {}).get("equipedSkills", [])
        },
        "GuildInfo": {
            "GuildCapacity": data.get("clanBasicInfo", {}).get("capacity"),
            "GuildID": str(data.get("clanBasicInfo", {}).get("clanId")),
            "GuildLevel": data.get("clanBasicInfo", {}).get("clanLevel"),
            "GuildMember": data.get("clanBasicInfo", {}).get("memberNum"),
            "GuildName": data.get("clanBasicInfo", {}).get("clanName"),
            "GuildOwner": str(data.get("clanBasicInfo", {}).get("captainId"))
        },
        "captainBasicInfo": data.get("captainBasicInfo", {}),
        "creditScoreInfo": data.get("creditScoreInfo", {}),
        "petInfo": data.get("petInfo", {}),
        "socialinfo": data.get("socialInfo", {})
    }

# === Caching Decorator ===

def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(request.args.items()))
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator

# === Flask Routes ===

@app.route('/get')
@cached_endpoint()
def get_account_info_formatted():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    if uid in uid_region_cache:
        try:
            return_data = asyncio.run(GetAccountInformation(uid, "7", uid_region_cache[uid], "/GetPlayerPersonalShow"))
            formatted = format_response(return_data)
            return jsonify(formatted)
        except Exception:
            pass

    for region in SUPPORTED_REGIONS:
        try:
            return_data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
            uid_region_cache[uid] = region
            formatted = format_response(return_data)
            return jsonify(formatted)
        except Exception as e:
            logging.debug(f"Region {region} failed: {e}")
            continue

    return jsonify({"error": "UID not found in any region."}), 404

@app.route('/player-info')
@cached_endpoint()
def get_account_info_raw():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    if uid in uid_region_cache:
        try:
            return_data = asyncio.run(GetAccountInformation(uid, "7", uid_region_cache[uid], "/GetPlayerPersonalShow"))
            formatted_json = json.dumps(return_data, indent=2, ensure_ascii=False)
            return formatted_json, 200, {'Content-Type': 'application/json; charset=utf-8'}
        except Exception:
            pass

    for region in SUPPORTED_REGIONS:
        try:
            return_data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
            uid_region_cache[uid] = region
            formatted_json = json.dumps(return_data, indent=2, ensure_ascii=False)
            return formatted_json, 200, {'Content-Type': 'application/json; charset=utf-8'}
        except Exception as e:
            logging.debug(f"Region {region} failed: {e}")
            continue

    return jsonify({"error": "UID not found in any region."}), 404

@app.route('/refresh', methods=['GET','POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'message': 'Tokens refreshed for all regions.'}), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}), 500

# === Startup ===

if __name__ == '__main__':
    print("Initializing tokens for all regions...")
    asyncio.run(initialize_tokens())
    print("Starting Flask server...")
    app.run(host='0.0.0.0', port=5000, debug=True)
