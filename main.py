import os
import hashlib
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

app = Flask(__name__)

CORS(app, origins=[
    "https://verser-phi.vercel.app",
])

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://verser-phi.vercel.app")

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


@app.route('/', methods=['GET'])
def index():
    return jsonify({"status": "ok", "message": "Backend VeriZh Chain is running!"})


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if data.get('username') == ADMIN_USERNAME and data.get('password') == ADMIN_PASSWORD:
        return jsonify({"success": True, "token": "access-granted-umrah"})
    return jsonify({"success": False, "message": "Username atau password salah"}), 401


@app.route('/issue-sertifikat', methods=['POST'])
def issue_sertifikat():
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
def get_all_sertifikat():
    try:
        result = supabase.table("sertifikat") \
            .select("id, nama_event, nama_lokasi, latitude, longitude, waktu_mulai, waktu_selesai, nama_peserta, keterangan, previous_hash, cert_hash, verify_url, created_at") \
            .order("id", desc=False) \
            .execute()
        return jsonify({"success": True, "data": result.data}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/verify/<hash_val>', methods=['GET'])
def verify(hash_val):
    try:
        result = supabase.table("sertifikat").select("*").eq("cert_hash", hash_val).execute()
        if result.data:
            return jsonify({"status": "VALID", "data": result.data[0]}), 200
        return jsonify({"status": "INVALID", "message": "Hash tidak ditemukan!"}), 404
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500


//made by grayesi anak keren//