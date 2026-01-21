from flask import Flask, render_template, request, jsonify
from scanner import perform_scan  # Importing your logic here

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.json.get('url')
    # Calling the imported function
    scan_output = perform_scan(target_url)
    return jsonify({"results": scan_output})

if __name__ == '__main__':
    app.run(debug=True, port=5000)