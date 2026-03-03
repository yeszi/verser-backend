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
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")  # bcrypt hash, bukan plaintext
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
    """SHA-256 hash dari block content untuk integritas sertifikat."""
    block_string = json.dumps(block_data, sort_keys=True).encode()
    return hashlib.sha256(block_string).hexdigest()


def get_last_block_hash() -> str:
    """
    Ambil hash block terakhir dari database untuk membentuk chain.
    Raise jika DB error agar chain tidak rusak.
    """
    result = supabase.table("sertifikat") \
        .select("cert_hash") \
        .order("id", desc=True) \
        .limit(1) \
        .execute()
    return result.data[0]['cert_hash'] if result.data else "0"


def is_authorized() -> bool:
    """Validasi JWT Bearer token dari Authorization header."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith("Bearer "):
        return False
    token = auth_header.replace("Bearer ", "").strip()
    if not token:
        return False
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return True
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False


def normalize_coordinate(value):
    """Normalize latitude/longitude ke float atau None untuk konsistensi hashing."""
    if value is None:
        return None
    return float(value)



@app.route('/', methods=['GET'])
def index():
    return jsonify({"status": "ok", "message": "Chain is running!"})


@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    """
    Login admin.
    - Username dicek duluan secara terpisah.
    - Password diverifikasi dengan bcrypt.
    - Pesan error generik agar tidak membocorkan info ke attacker.
    """
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"success": False, "message": "Request tidak valid"}), 400

    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({"success": False, "message": "Username dan password wajib diisi"}), 400

    if username != ADMIN_USERNAME:
        logger.warning(f"Login gagal: username tidak dikenal dari IP {request.remote_addr}")
        return jsonify({"success": False, "message": "Username atau password salah"}), 401

    try:

        password_match = bcrypt.checkpw(
            password.encode('utf-8'),
            ADMIN_PASSWORD_HASH.encode('utf-8')
        )

        if not password_match:
            logger.warning(f"Login gagal: password salah dari IP {request.remote_addr}")
            return jsonify({"success": False, "message": "Username atau password salah"}), 401

        payload = {
            "sub": "admin",
            "iat": datetime.datetime.utcnow(),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=8)
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        return jsonify({"success": True, "token": token}), 200

    except Exception:
        logger.exception("Login: unexpected error")
        return jsonify({"success": False, "message": "Terjadi kesalahan server"}), 500


@app.route('/issue-sertifikat', methods=['POST'])
@limiter.limit("30 per minute")
def issue_sertifikat():
    if not is_authorized():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"success": False, "message": "Request tidak valid"}), 400

        prev_hash = get_last_block_hash()

        latitude  = normalize_coordinate(data.get('latitude'))
        longitude = normalize_coordinate(data.get('longitude'))

        block_content = {
            "nama_event"    : data['nama_event'],
            "nama_lokasi"   : data['nama_lokasi'],
            "latitude"      : latitude,
            "longitude"     : longitude,
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

    except KeyError as e:
        return jsonify({"success": False, "message": f"Field wajib tidak ada: {e}"}), 400

    except Exception as e:
        logger.exception("issue-sertifikat: unexpected error")
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
        logger.exception("get_all_sertifikat: unexpected error")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/verify/<string:hash_val>', methods=['GET'])
@limiter.limit("20 per minute")
def verify(hash_val):
    # Validasi format hash — SHA-256 selalu 64 karakter hex
    if not hash_val or len(hash_val) != 64 or not all(c in '0123456789abcdefABCDEF' for c in hash_val):
        return jsonify({"status": "INVALID", "message": "Format hash tidak valid"}), 400

    try:
        result = supabase.table("sertifikat").select(
            "nama_event, nama_lokasi, latitude, longitude, waktu_mulai, waktu_selesai, nama_peserta, keterangan, previous_hash, cert_hash, verify_url, created_at"
        ).eq("cert_hash", hash_val).execute()

        if not result.data:
            return jsonify({"status": "INVALID", "message": "Hash tidak ditemukan!"}), 404

        record = result.data[0]

        latitude  = normalize_coordinate(record["latitude"])
        longitude = normalize_coordinate(record["longitude"])

        # Hitung ulang hash dari data tersimpan untuk verifikasi integritas
        block_content = {
            "nama_event"    : record["nama_event"],
            "nama_lokasi"   : record["nama_lokasi"],
            "latitude"      : latitude,
            "longitude"     : longitude,
            "waktu_mulai"   : record["waktu_mulai"],
            "waktu_selesai" : record["waktu_selesai"],
            "nama_peserta"  : record["nama_peserta"],
            "keterangan"    : record["keterangan"],
            "previous_hash" : record["previous_hash"]
        }

        recomputed_hash = calculate_hash(block_content)

        if recomputed_hash != record["cert_hash"]:
            logger.warning(f"Hash mismatch terdeteksi untuk cert_hash: {hash_val}")
            return jsonify({"status": "INVALID", "message": "Data sertifikat telah dimanipulasi!"}), 400

        return_data = {
            "nama_event"   : record["nama_event"],
            "nama_lokasi"  : record["nama_lokasi"],
            "waktu_mulai"  : record["waktu_mulai"],
            "waktu_selesai": record["waktu_selesai"],
            "nama_peserta" : record["nama_peserta"],
            "keterangan"   : record["keterangan"],
            "cert_hash"    : record["cert_hash"],
            "verify_url"   : record["verify_url"],
            "created_at"   : record["created_at"]
        }

        return jsonify({"status": "VALID", "data": return_data}), 200

    except Exception as e:
        logger.exception("verify: unexpected error")
        return jsonify({"status": "ERROR", "message": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=False)
