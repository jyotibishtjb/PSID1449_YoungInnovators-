from flask import Flask, render_template, request, redirect, url_for
import json
import re

app = Flask(__name__)

def fetch_vulnerability_info(cpe_value, database_path='data.json'):
    with open(database_path, 'r', encoding='utf-8') as file:
        database = json.load(file)

    for vulnerability in database['CVE_Items']:
        for node in vulnerability['configurations']['nodes']:
            for cpe_match in node.get('cpe_match', []):
                cpe_uri = cpe_match.get('cpe23Uri', '')
                cpe_pattern = re.escape(cpe_value)
                if re.match(cpe_pattern, cpe_uri):
                    return vulnerability

    return None

def generate_html(result):
    if result:
        # Extract impact information
        impact = result.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {})

        # Prepare dynamic values
        dynamic_values = {
            'CVE_ID': result['cve']['CVE_data_meta']['ID'],
            'DESCRIPTION': result['cve']['description']['description_data'][0]['value'],
            'VERSION': impact.get('version', ''),
            'VECTOR_STRING': impact.get('vectorString', ''),
            'ATTACK_VECTOR': impact.get('attackVector', ''),
            'ATTACK_COMPLEXITY': impact.get('attackComplexity', ''),
            'PRIVILEGES_REQUIRED': impact.get('privilegesRequired', ''),
            'USER_INTERACTION': impact.get('userInteraction', ''),
            'SCOPE': impact.get('scope', ''),
            'CONFIDENTIALITY_IMPACT': impact.get('confidentialityImpact', ''),
            'INTEGRITY_IMPACT': impact.get('integrityImpact', ''),
            'AVAILABILITY_IMPACT': impact.get('availabilityImpact', ''),
            'BASE_SCORE': impact.get('baseScore', ''),
            'BASE_SEVERITY': impact.get('baseSeverity', ''),
        }

        return render_template('vulnerability_information.html', dynamic_values=dynamic_values)
    else:
        return render_template('error.html', message=f"No vulnerability found for CPE value: {cpe_value}")

def save_to_json(result):
    if result:
        with open('output.json', 'w', encoding='utf-8') as json_file:
            json.dump(result, json_file)
        return redirect(url_for('show_json'))
    else:
        return render_template('error.html', message=f"No vulnerability found for CPE value: {cpe_value}")

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        cpe_value_input = request.form['cpe_value']
        result = fetch_vulnerability_info(cpe_value_input)
        return save_to_json(result)
    return render_template('index.html')

@app.route('/json')
def show_json():
    with open('output.json', 'r', encoding='utf-8') as json_file:
        data = json.load(json_file)
    return render_template('show_json.html', data=data)

if __name__ == '__main__':
    app.run(debug=True)
