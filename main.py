import os
import hashlib
import json
import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from supabase import create_client, Client
import jwt

load_dotenv()

app = Flask(__name__)

CORS(app, origins=[
    "https://verser-phi.vercel.app",
])

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour"]
)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://verser-phi.vercel.app")
JWT_SECRET = os.getenv("JWT_SECRET")

for var_name, var_val in [("SUPABASE_URL", SUPABASE_URL), ("SUPABASE_KEY", SUPABASE_KEY),
                           ("ADMIN_USERNAME", ADMIN_USERNAME), ("ADMIN_PASSWORD", ADMIN_PASSWORD),
                           ("JWT_SECRET", JWT_SECRET)]:
    if not var_val:
        raise RuntimeError(f"{var_name} tidak boleh kosong!")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


def calculate_hash(block_data):
    block_string = json.dumps(block_data, sort_keys=True).encode()
    return hashlib.sha256(block_string).hexdigest()


def get_last_block_hash():
    try:
        result = supabase.table("sertifikat").select("cert_hash").order("id", desc=True).limit(1).execute()
        return result.data[0]['cert_hash'] if result.data else "0"
    except:
        return "0"


def is_authorized():
    token = request.headers.get('Authorization', '').replace("Bearer ", "")
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return True
    except Exception:
        return False


@app.route('/', methods=['GET'])
def index():
    return jsonify({"status": "ok", "message": "Chain is running!"})


@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.json
    if data.get('username') == ADMIN_USERNAME and data.get('password') == ADMIN_PASSWORD:
        payload = {
            "sub": "admin",
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=8)
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        return jsonify({"success": True, "token": token})
    return jsonify({"success": False, "message": "Username atau password salah"}), 401


@app.route('/issue-sertifikat', methods=['POST'])
@limiter.limit("30 per minute")
def issue_sertifikat():
    if not is_authorized():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    try:
        data = request.json
        prev_hash = get_last_block_hash()

        latitude = data.get('latitude')
        longitude = data.get('longitude')
        if latitude:
            latitude = float(latitude)
        if longitude:
            longitude = float(longitude)

        block_content = {
            "nama_event":    data['nama_event'],
            "nama_lokasi":   data['nama_lokasi'],
            "latitude":      latitude,
            "longitude":     longitude,
            "waktu_mulai":   data['waktu_mulai'],
            "waktu_selesai": data['waktu_selesai'],
            "nama_peserta":  data['nama_peserta'],
            "keterangan":    data.get('keterangan', ''),
            "previous_hash": prev_hash
        }

        cert_hash = calculate_hash(block_content)
        verify_url = f"{FRONTEND_URL}/verify/{cert_hash}"

        insert_data = {
            "nama_event":    data['nama_event'],
            "nama_lokasi":   data['nama_lokasi'],
            "latitude":      latitude,
            "longitude":     longitude,
            "waktu_mulai":   data['waktu_mulai'],
            "waktu_selesai": data['waktu_selesai'],
            "nama_peserta":  data['nama_peserta'],
            "keterangan":    data.get('keterangan', ''),
            "previous_hash": prev_hash,
            "cert_hash":     cert_hash,
            "verify_url":    verify_url
        }

        supabase.table("sertifikat").insert(insert_data).execute()
        return jsonify({"success": True, "hash": cert_hash, "verify_url": verify_url}), 201

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/sertifikat', methods=['GET'])
@limiter.limit("60 per minute")
def get_all_sertifikat():
    if not is_authorized():
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    try:
        result = supabase.table("sertifikat") \
            .select("id, nama_event, nama_lokasi, latitude, longitude, waktu_mulai, waktu_selesai, nama_peserta, keterangan, previous_hash, cert_hash, verify_url, created_at") \
            .order("id", desc=False) \
            .execute()
        return jsonify({"success": True, "data": result.data}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/verify/<hash_val>', methods=['GET'])
@limiter.limit("20 per minute")
def verify(hash_val):
    try:
        # Ambil semua field yang dibutuhkan untuk verifikasi integritas
        result = supabase.table("sertifikat").select(
            "nama_event, nama_lokasi, latitude, longitude, waktu_mulai, waktu_selesai, nama_peserta, keterangan, previous_hash, cert_hash, verify_url, created_at"
        ).eq("cert_hash", hash_val).execute()

        # Hash tidak ditemukan sama sekali di database
        if not result.data:
            return jsonify({"status": "INVALID", "message": "Hash tidak ditemukan!"}), 404

        record = result.data[0]

        # Hitung ulang hash dari data yang tersimpan di database
        block_content = {
            "nama_event":    record["nama_event"],
            "nama_lokasi":   record["nama_lokasi"],
            "latitude":      record["latitude"],
            "longitude":     record["longitude"],
            "waktu_mulai":   record["waktu_mulai"],
            "waktu_selesai": record["waktu_selesai"],
            "nama_peserta":  record["nama_peserta"],
            "keterangan":    record["keterangan"],
            "previous_hash": record["previous_hash"]
        }
        recomputed_hash = calculate_hash(block_content)

        if recomputed_hash != record["cert_hash"]:
            return jsonify({"status": "INVALID", "message": "Data sertifikat telah dimanipulasi!"}), 400

        return_data = {
            "nama_event":    record["nama_event"],
            "nama_lokasi":   record["nama_lokasi"],
            "waktu_mulai":   record["waktu_mulai"],
            "waktu_selesai": record["waktu_selesai"],
            "nama_peserta":  record["nama_peserta"],
            "keterangan":    record["keterangan"],
            "cert_hash":     record["cert_hash"],
            "verify_url":    record["verify_url"],
            "created_at":    record["created_at"]
        }
        return jsonify({"status": "VALID", "data": return_data}), 200

    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500