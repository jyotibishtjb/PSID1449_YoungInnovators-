from flask import Flask, render_template,send_file,request, session, jsonify,redirect,url_for
from werkzeug.utils import secure_filename
import os
import PyPDF2
import json
import requests
import response

app = Flask(__name__)
app.secret_key = 'jrhfigaewhiugiuhiuwgihpeeuhwupg'  # Change this to a secure secret key
UPLOAD_FOLDER = r'C:\Users\mitta\OneDrive - galgotiasuniversity.edu.in\Desktop\SIH Landing page Flask\uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)



@app.route('/')
def index():
    return render_template('chat.html')



#file upload
@app.route('/file')

def about():
    return render_template('file.html')

@app.route('/files',methods=['POST'])
def upload_file():
    
    file_keys = ['file1', 'file2', 'file3']
    files = []

    for key in file_keys:
        file_list = request.files.getlist(key)
        files.extend(file_list)  # Get all uploaded files
    print(len(files))
    # Check if any files were uploaded
    if not files:
        return jsonify({'error': 'No files uploaded'})

    # Process each uploaded file
    session['file_paths'] = []
    for file in files:
        if file.filename == '':
            continue  # Skip empty files

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        print(file_path)
        # Store the file path in the session
        session['file_paths'].append(file_path)

    return jsonify({'success': True})



@app.route('/process', methods=['GET'])
def process_file():
    file_paths = session.get('file_paths', None)

    if not file_paths:
        return jsonify({'error': 'No files uploaded'})
    # Remove the dot from the extension
    results = []
    for file_path in file_paths:
        # Determine the file type and process accordingly
        _, file_extension = os.path.splitext(file_path)
        file_type = file_extension.lower()[1:]

        if file_type == 'txt':
                with open(file_path, 'r') as txt_file:
                    result = f'Text content: {txt_file.read()}'
        elif file_type == 'pdf':
            text = ""
            with open(file_path, 'rb') as pdf_file:
                pdf_reader = PyPDF2.PdfReader(pdf_file)
                for page_num in range(len(pdf_reader.pages)):
                    page = pdf_reader.pages[page_num]
                    text += page.extract_text()
                
            result = f'PDF content: {text}'
            
        elif file_type == 'json':
            with open(file_path, 'r') as json_file:
                json_data = json.load(json_file)
                result = f'JSON data: {json_data}'

        results.append(result)
        print(result)
    # Clear the list of paths after processing
    session.pop('file_paths', None)

    # Combine results with GPT-4 response
    

    cve_results = json.loads(response.choices[0].message.content)
    session['cve_results'] = cve_results
    print(cve_results)
    output_folder_path = 'backend\outputs_folder'

    # Create the output_folder if it doesn't exist
    if not os.path.exists(output_folder_path):
        os.makedirs(output_folder_path)

    output_file_path = os.path.join(output_folder_path, 'displayy_results.json')
    with open(output_file_path, 'w') as output_file:
        json.dump(cve_results, output_file, indent=2)

    
    # return jsonify({'results': results, 'assistant_response': cve_results})

    try:
       
        if  "SoftwareBillOfMaterials" in cve_results:
            components = cve_results["SoftwareBillOfMaterials"]

            if components:
                for component in components:
                    if "cpe" in component:
                        cpe_value = component["cpe"]
                        cpe_parts = cpe_value.split(":")

                        if len(cpe_parts) == 5 and cpe_parts[1] == "/a":
                            part_name_a = cpe_parts[1].split("/")
                            part_name = part_name_a[1]
                            vendor_name = cpe_parts[2]
                            product_name = cpe_parts[3]                          
                        
                       
                            cpe_value = f"cpe:2.3:{part_name}:{vendor_name}:{product_name}:*"
                        # Redirect to the new route with parameters as query parameters
                        print(cpe_value)
                        return redirect(url_for('new_route', cpe_value=cpe_value))

                         # Exit the function after processing the first matching component

          
 
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        print(f"Error processing CVE data: {e}")
    return redirect(url_for('displayy_results',cve_results=cve_results))

@app.route('/sbom')
def sbom():
    return render_template('table.html')
    
@app.route('/get_json_data')
def get_json_data():
    # Assuming your JSON file is in the 'output_folder' directory
    
    # a=send_file(json_file_path, mimetype='application/json')
    # return render_template('sbom.html', json_data=a) 

    return send_file('displayy_results.json', mimetype='application/json')

    
@app.route('/new_route', methods=['GET'])
def new_route():
    # Access parameters from the query string
    cpe_value = request.args.get('cpe_value')
    api_key = "f0ded9f3-033e-4b5a-8054-ba2270e0c51b"
    base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"

    # Construct the search URL with the cpeMatchString parameter
    search_url = f"{base_url}?cpeMatchString={cpe_value}"

    try:
        # Include the API key in the request headers
        headers = {'apikey': api_key}
        response = requests.get(search_url, headers=headers)

        if response.status_code == 200:
            search_results = response.json()
            
            # Process the response here...

            # Check if the response is empty
            if not search_results:
                return jsonify({'error': 'No CVEs found for the specified CPE.'})

            # Processing of raw data (search_results)
            if isinstance(search_results, dict) and 'result' in search_results:
                cve_items = search_results['result']['CVE_Items']
                if cve_items:
                    result_data = []
                    for idx, cve_item in enumerate(cve_items):
                        cve_id = cve_item['cve']['CVE_data_meta']['ID']
                        print(f"{idx + 1}. CVE ID: {cve_id}")

                        # Extract CVSS information
                        impact = cve_item.get('impact', {})
                        base_metric_v3 = impact.get('baseMetricV3', {})

                        # Extract CVSS information, checking for key existence
                        cvss_base_score = base_metric_v3.get('cvssV3', {}).get('baseScore', 'N/A')
                        cvss_severity = base_metric_v3.get('cvssV3', {}).get('baseSeverity', 'N/A')

                        # Extract more detailed CVSS information
                        cvss_vector = base_metric_v3.get('cvssV3', {}).get('vectorString', 'N/A')
                        exploitability_score = base_metric_v3.get('exploitabilityScore', 'N/A')
                        impact_score = base_metric_v3.get('impactScore', 'N/A')

                        # Extract additional information
                        published_date = cve_item.get('publishedDate', 'N/A')
                        last_modified_date = cve_item.get('lastModifiedDate', 'N/A')

                        # Additional information can be printed or processed as needed
                        description = cve_item['cve']['description']['description_data'][0]['value']
                        print(f"   Description: {description}")
                        print(f"   Published Date: {published_date}")
                        print(f"   Last Modified Date: {last_modified_date}")
                        print(f"   CVSS Base Score: {cvss_base_score}")
                        print(f"   CVSS Severity: {cvss_severity}")
                        print(f"   CVSS Vector: {cvss_vector}")
                        print(f"   Exploitability Score: {exploitability_score}")
                        print(f"   Impact Score: {impact_score}\n")

                        # Prepare data for saving to JSON
                        cve_data = {
                            "CVE_ID": cve_id,
                            "Description": description,
                            "Published_Date": published_date,
                            "Last_Modified_Date": last_modified_date,
                            "CVSS_Base_Score": cvss_base_score,
                            "CVSS_Severity": cvss_severity,
                            "CVSS_Vector": cvss_vector,
                            "Exploitability_Score": exploitability_score,
                            "Impact_Score": impact_score
                        }
                        result_data.append(cve_data)
                    print(result_data)
                    # Save the result to a JSON file
                    output_folder = "backend\output_folder"
                    output_file_path = os.path.join(output_folder, "cve_results.json")
                    with open(output_file_path, 'w') as json_file:
                        json.dump(result_data, json_file, indent=2)
                    print(f"\nResults saved to: {output_file_path}")

                else:
                    print("No CVEs found for the specified CPE.")
            else:
                print("Invalid response format.")

            # Return a response, for example, a JSON response
            return jsonify(search_results)

        else:
            return jsonify({'error': f"Error: {response.status_code}"})

    except Exception as e:
        print(f"An error occurred: {e}")
        # Return an error response if needed
        return jsonify({'error': f"An error occurred: {e}"})


@app.route('/result')
def result():
    return render_template('chart2.html')
    
@app.route('/get_jsonn_data')
def get_jsonn_data():
   

    return send_file('card.json', mimetype='application/json')



if __name__ == '__main__':
    app.run(debug=True, port = 8000)
