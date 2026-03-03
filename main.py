import os
import hashlib
import json
import datetime
import logging
import bcrypt
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
from supabase import create_client, Client
import jwt

logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s %(levelname)s %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

CORS(app, origins=[
    "https://verser-phi.vercel.app",
])

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour"]
)

SUPABASE_URL        = os.getenv("SUPABASE_URL")
SUPABASE_KEY        = os.getenv("SUPABASE_KEY")
ADMIN_USERNAME      = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")  
FRONTEND_URL        = os.getenv("FRONTEND_URL", "https://verser-phi.vercel.app")
JWT_SECRET          = os.getenv("JWT_SECRET")

_required_env = {
    "SUPABASE_URL"        : SUPABASE_URL,
    "SUPABASE_KEY"        : SUPABASE_KEY,
    "ADMIN_USERNAME"      : ADMIN_USERNAME,
    "ADMIN_PASSWORD_HASH" : ADMIN_PASSWORD_HASH,
    "JWT_SECRET"          : JWT_SECRET,
}
for var_name, var_val in _required_env.items():
    if not var_val:
        raise RuntimeError(f"{var_name} tidak boleh kosong!")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


def calculate_hash(block_data: dict) -> str:
    """
    SHA-256 hash dari block content. 
    sort_keys=True sangat krusial agar urutan JSON selalu sama (Idempotent).
    """
    block_string = json.dumps(block_data, sort_keys=True).encode()
    return hashlib.sha256(block_string).hexdigest()

def get_last_block_hash() -> str:
    """Ambil hash block terakhir untuk membentuk chain."""
    result = supabase.table("sertifikat") \
        .select("cert_hash") \
        .order("id", desc=True) \
        .limit(1) \
        .execute()
    return result.data[0]['cert_hash'] if result.data else "0"

def normalize_coordinate(value):
    """Normalize koordinat agar tetap konsisten saat hashing ulang."""
    if value is None:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None

def is_authorized() -> bool:
    """Validasi JWT Bearer token."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith("Bearer "):
        return False
    token = auth_header.replace("Bearer ", "").strip()
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return True
    except Exception:
        return False


@app.route('/', methods=['GET'])
def index():
    return jsonify({"status": "ok", "message": "Blockchain Core is running!"})

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Request tidak valid"}), 400

    username = data.get('username', '').strip()
    password = data.get('password', '')

    if username != ADMIN_USERNAME:
        return jsonify({"success": False, "message": "Username atau password salah"}), 401

    try:
        password_match = bcrypt.checkpw(
            password.encode('utf-8'),
            ADMIN_PASSWORD_HASH.encode('utf-8')
        )
        if not password_match:
            return jsonify({"success": False, "message": "Username atau password salah"}), 401

        payload = {
            "sub": "admin",
            "iat": datetime.datetime.utcnow(),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=8)
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        return jsonify({"success": True, "token": token}), 200
    except Exception:
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route('/issue-sertifikat', methods=['POST'])
@limiter.limit("30 per minute")
def issue_sertifikat():
    if not is_authorized():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        data = request.get_json(silent=True)
        prev_hash = get_last_block_hash()

        # Data yang masuk ke block_content harus sama persis strukturnya dengan saat verifikasi
        block_content = {
            "nama_event"    : data['nama_event'],
            "nama_lokasi"   : data['nama_lokasi'],
            "latitude"      : normalize_coordinate(data.get('latitude')),
            "longitude"     : normalize_coordinate(data.get('longitude')),
            "waktu_mulai"   : data['waktu_mulai'],
            "waktu_selesai" : data['waktu_selesai'],
            "nama_peserta"  : data['nama_peserta'],
            "keterangan"    : data.get('keterangan', ''),
            "previous_hash" : prev_hash
        }

        cert_hash  = calculate_hash(block_content)
        verify_url = f"{FRONTEND_URL}/verify/{cert_hash}"

        insert_data = {
            **block_content,
            "cert_hash"  : cert_hash,
            "verify_url" : verify_url
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
        result = supabase.table("sertifikat").select("*").order("id", desc=False).execute()
        return jsonify({"success": True, "data": result.data}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/verify/<string:hash_val>', methods=['GET'])
@limiter.limit("20 per minute")
def verify(hash_val):
    """Verifikasi integritas sertifikat tunggal."""
    try:
        result = supabase.table("sertifikat").select("*").eq("cert_hash", hash_val).execute()

        if not result.data:
            return jsonify({"status": "INVALID", "message": "Sertifikat tidak ditemukan!"}), 404

        record = result.data[0]

        # RE-CALCULATE: Hitung ulang hash dari data yang ada di DB sekarang
        current_data_state = {
            "nama_event"    : record["nama_event"],
            "nama_lokasi"   : record["nama_lokasi"],
            "latitude"      : normalize_coordinate(record["latitude"]),
            "longitude"     : normalize_coordinate(record["longitude"]),
            "waktu_mulai"   : record["waktu_mulai"],
            "waktu_selesai" : record["waktu_selesai"],
            "nama_peserta"  : record["nama_peserta"],
            "keterangan"    : record["keterangan"],
            "previous_hash" : record["previous_hash"]
        }

        actual_hash = calculate_hash(current_data_state)

        if actual_hash != record["cert_hash"]:
            return jsonify({
                "status": "INVALID", 
                "message": "Peringatan: Data sertifikat ini telah dimanipulasi secara ilegal!",
                "debug": {"expected": record["cert_hash"], "actual": actual_hash}
            }), 400

        return jsonify({"status": "VALID", "data": record}), 200

    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.route('/audit-chain', methods=['GET'])
@limiter.limit("10 per minute")
def audit_chain():
    """Rute khusus skripsi: Mengecek seluruh integritas database."""
    try:
        result = supabase.table("sertifikat").select("*").order("id", desc=False).execute()
        chain = result.data
        issues = []

        for i in range(len(chain)):
            curr = chain[i]
            
            # 1. Cek apakah data blok ini masih sesuai dengan hash-nya sendiri
            content = {
                "nama_event"    : curr['nama_event'],
                "nama_lokasi"   : curr['nama_lokasi'],
                "latitude"      : normalize_coordinate(curr['latitude']),
                "longitude"     : normalize_coordinate(curr['longitude']),
                "waktu_mulai"   : curr['waktu_mulai'],
                "waktu_selesai" : curr['waktu_selesai'],
                "nama_peserta"  : curr['nama_peserta'],
                "keterangan"    : curr.get('keterangan', ''),
                "previous_hash" : curr['previous_hash']
            }
            if calculate_hash(content) != curr['cert_hash']:
                issues.append(f"Blok {curr['id']} (Sertifikat {curr['nama_peserta']}): Data dimodifikasi manual.")

            # 2. Cek apakah rantai terhubung ke blok sebelumnya
            if i > 0:
                prev = chain[i-1]
                if curr['previous_hash'] != prev['cert_hash']:
                    issues.append(f"Rantai Terputus: Blok {curr['id']} tidak merujuk ke Blok {prev['id']}.")

        if issues:
            return jsonify({"status": "CORRUPTED", "message": "Integritas rantai rusak!", "errors": issues}), 400
        
        return jsonify({"status": "SECURE", "message": "Seluruh data valid dan rantai utuh."}), 200

    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=False)