from flask import Flask, render_template, request, session
import re
import os
from flask_session import Session

# Generate a secure random key
secret_key = os.urandom(24)

app = Flask(__name__)
app.secret_key = secret_key.hex()  # Set a secret key for session management
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# texts = []

# \d = [0-9]
# \b (digits) \b = ensures that the (digits) are not part of a longer sequence
# Define the regular expression pattern
ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
method_pattern = r"GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS"
path_pattern = r"(?:" + method_pattern + r")\s(.*?)\s"
# status = r"\b[1-5]\d{2}\b"
status_pattern = r"(?<=\s)[1-5]\d{2}(?=\s)"


def parse_texts(texts):
    results = []
    seen_ips = set()  # Set to track seen IPs

    for text in texts:
        result = {}
        ip_match = re.search(ip_pattern, text)
        if ip_match:
            ip = ip_match.group()
            if ip in seen_ips:
                continue  # Skip if IP is already seen
            seen_ips.add(ip)
            result['ip'] = ip
        else:
            result['ip'] = 'No IP match found.'

        results.append(result)
    return results

def filter_by_ip(ip):
    unique_pairs = set()  # Set to track unique (method, path) pairs
    results = []
    counts = {}
    texts = session.get('texts')
    for text in texts:
        if ip in text:
            result = {}

            method_match = re.search(method_pattern, text)
            if method_match:
                method = method_match.group()
                result['method'] = method
            else:
                result['method'] = 'No method match found.'

            path_match = re.search(path_pattern, text)
            if path_match:
                path = path_match.group(1)
                result['path'] = path
            else:
                result['path'] = 'No path match found.'

            status_match = re.search(status_pattern, text)
            if status_match:
                result['status'] = status_match.group()
            else:
                result['status'] = 'No http status match found.'

            method_path_pair = (result.get('method'), result.get('path'))
            counts[method_path_pair] = counts.get(method_path_pair, 0) + 1

            if method_path_pair not in unique_pairs:
                unique_pairs.add(method_path_pair)
                results.append(result)
            #results.append(result)

    for result in results:
        method_path_pair = (result.get('method'), result.get('path'))
        result['count'] = counts[method_path_pair]

    return results



@app.route('/')
def index():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload():
    # global texts
    file = request.files['file']
    if not file:
        return "No file uploaded", 400

    texts = file.read().decode('utf-8').split('\n')
    parsed_data = parse_texts(texts)
    session['texts'] = texts  # Store texts in session
    return render_template('index.html', parsed_data=parsed_data)

@app.route('/<ip>')
def show_detail(ip):
    filtered_data = filter_by_ip(ip)
    return render_template('detail.html', filtered_data=filtered_data, ip=ip)


if __name__ == '__main__':
    app.run(debug=True)