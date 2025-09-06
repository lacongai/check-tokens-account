from flask import Flask, request, jsonify
import json, os, zipfile, datetime, jwt
from prettytable import PrettyTable  # Thư viện in bảng đẹp

app = Flask(__name__)

# ================== Hàm check token ==================
def check_token_valid(token):
    """Decode JWT token không cần verify chữ ký, chỉ check exp còn hạn hay không."""
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        exp_ts = decoded.get("exp")
        if not exp_ts:
            return True, "No exp field", None
        exp_time = datetime.datetime.fromtimestamp(exp_ts)
        now = datetime.datetime.utcnow()
        if exp_time < now:
            return False, f"Token expired at {exp_time}", exp_time
        return True, f"Token valid until {exp_time}", exp_time
    except Exception as e:
        return False, f"Invalid token: {e}", None


# ================== API Check Token/File ==================
@app.route('/api/check_token_file', methods=['GET'])
def check_token_file():
    # ✅ Check key bảo mật
    key = request.args.get("key")
    if key != "hentaiz":
        return jsonify({"error": "Unauthorized. Invalid key!"}), 403

    token_file = request.args.get("token_file")
    if not token_file:
        return jsonify({"error": "token_file parameter is required"}), 400

    tokens = []

    # ----- Nếu là file (json/js/zip) -----
    if os.path.exists(token_file):
        try:
            if token_file.endswith(".zip"):
                with zipfile.ZipFile(token_file, "r") as zip_ref:
                    extract_dir = "extracted_tokens"
                    zip_ref.extractall(extract_dir)
                    for fname in os.listdir(extract_dir):
                        if fname.endswith(".json") or fname.endswith(".js"):
                            with open(os.path.join(extract_dir, fname), "r", encoding="utf-8") as f:
                                content = f.read()
                                if fname.endswith(".js"):
                                    start = content.find("{")
                                    end = content.rfind("}")
                                    content = content[start:end+1]
                                tokens.extend(json.loads(content))
            else:
                with open(token_file, "r", encoding="utf-8") as f:
                    content = f.read()
                    if token_file.endswith(".js"):
                        start = content.find("{")
                        end = content.rfind("}")
                        content = content[start:end+1]
                    tokens = json.loads(content)
        except Exception as e:
            return jsonify({"error": f"Error reading file: {e}"}), 500

        if not isinstance(tokens, list):
            return jsonify({"error": "File format invalid, expected a list of tokens"}), 400

        source = token_file

    # ----- Nếu là chuỗi token trực tiếp -----
    else:
        tokens = [token_file]
        source = "direct_token"

    # ----- Check từng token -----
    results = []
    table = PrettyTable(["#", "Status", "Message", "Exp", "Token (short)"])
    for idx, t in enumerate(tokens, start=1):
        token = t.get("token", "") if isinstance(t, dict) else t
        is_valid, msg, exp_time = check_token_valid(token)
        short_token = token[:20] + "..." if token else ""
        results.append({
            "index": idx,
            "status": "valid" if is_valid else "invalid",
            "message": msg,
            "exp": str(exp_time) if exp_time else None,
            "token_short": short_token
        })
        table.add_row([idx, "✅" if is_valid else "❌", msg, exp_time, short_token])

    return jsonify({
        "source": source,
        "total_tokens": len(tokens),
        "results": results,
        "table": str(table)  # in bảng ra dưới dạng text
    })


# ================== Main ==================
if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)