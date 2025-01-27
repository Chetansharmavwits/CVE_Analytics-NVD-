# Script for converting json to excel, then read excel and match with main repository file and fetch component name and product name from NVD which are found then append 
# in main repository other wise creat missing component file.
import json
import requests
import pandas as pd
import time
import logging
import os
import time
from datetime import timedelta, datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import warnings
import streamlit as st
warnings.filterwarnings("ignore")

yellow = "\033[33m"
reset = "\033[0m"
green = "\033[32m"
red = "\033[31m"
cyan = "\033[36m"


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()


def json_to_excel(json_path)->pd.DataFrame:
    '''
    Convert Json File to Excel file.
    '''
    # with open(json_path, 'r', encoding='utf-16') as file:
    #     data = json.load(file)
    
    data = json.load(json_path)

    # Access the 'Type' attribute from each dictionary in the list
    products = data[1].get('Products')
    data_list = []
    for product in products:
        module = product.get('module')
        file_name = product.get('info').get('filename')
        # file_without_ext = file_name.replace(".dll", "")
        company_name = product.get('info').get('companyName')
        product_description = product.get('info').get('productDescription')
        product_version = product.get('info').get('productVersion')
        product_name = product.get('info').get('productName')

        data_list.append({
                            'Module': module,
                            'File Name': file_name,
                            'Product Name': product_name,
                            'Product Description': product_description,
                            'Company Name': company_name,
                            'Product Version': product_version    
                        })
    df = pd.DataFrame(data_list)
    df_unique = df.drop_duplicates(subset=['Module','File Name', 'Product Description'])
    return df_unique

def merge_product_component(file1: pd.DataFrame, file2: str) -> pd.DataFrame:
    df2 = pd.read_excel(file2, engine='openpyxl') 
    file_to_component = df2.set_index('File Name')['Component Name'].to_dict()
    
    try:
        file1['Component Name'] =file1.apply(
            lambda row:row['Component Name']
            if pd.notna(row['Component Name']) and row['File Name'] not in file_to_component
            else file_to_component.get(row['File Name'],row['Component Name']),
            axis= 1
        )
    except:
        file1['Component Name'] = file1['File Name'].map(file_to_component)
   
        
        
    output_columns_file1 = ['Module', 'File Name', 'Company Name', 'Product Name', 'Component Name', 'Product Description',  'Product Version']
    output_columns_df2 = ['File Name', 'Component Name']
    return file1[output_columns_file1], df2[output_columns_df2]


def generate_dynamic_url(keyword, severity):
    API_URL = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&cvssV3Severity={severity}"
    return API_URL


def search_nvd(keyword, severity, api_key):
    API_URL = generate_dynamic_url(keyword, severity)
  
    headers = {
        'Authorization': f'Bearer {api_key}'
    }

    params = {
        'resultsPerPage': 2000,  
        'startIndex': 0
    }

    all_cves = []

    session = requests.Session()
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('https://', HTTPAdapter(max_retries=retries))

    while True:
        print(f" * Making request to: {API_URL} with params: {params}")
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = session.get(API_URL, params=params, headers=headers)
                break  # Exit the loop if successful
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError) as e:
                    print(f"*** Connection error encountered: {e}. Attempt {attempt + 1} of {max_retries}.")
                # Retry logic with a maximum of 3 attempts
            if attempt < max_retries - 1:
                print("Retrying...")
                time.sleep(30)  # Wait for 30 seconds before retrying
            else:
                print("Max retries reached. Moving to the next component.")
                time.sleep(30)
                continue  # Retry the same request after sleep
        
        if response.status_code == 200:
            data = response.json()
            print(f"* API Response for {keyword} with severity {severity}")
        
            if 'vulnerabilities' in data:
                cves = data['vulnerabilities']
                print(f"* Found {len(cves)} CVEs for {keyword}")

                if len(cves) == 0:
                   print(f"{red}** No CVEs found for {keyword} with severity {severity}{reset}")
                
                for cve in cves:
                    cve_id = cve['cve']['id']
                    descriptions = cve['cve']['descriptions']
                    description = next((d['value'] for d in descriptions if d['lang'] == 'en'), "No description available")
                    if 'cvssMetricV30' in cve['cve']['metrics']:
                        for metric in cve['cve']['metrics']['cvssMetricV30']:
                            cvss_v30_source = metric.get('source', "")
                            cvss_v30_type = metric.get('type', "")
                            cvss_v30 = metric.get('cvssData', {})
                            if cvss_v30:
                                cvss_v30_base_score = cvss_v30.get('baseScore', 0)
                                cvss_v30_severity = cvss_v30.get('baseSeverity', "")
                                cvss_v30_vectorString = cvss_v30.get('vectorString', "")
                                all_cves.append({
                                                'Component Name': keyword,
                                                'CVE ID': cve_id,
                                                'Descriptions': description,
                                                'Type': cvss_v30_type,
                                                'Source': cvss_v30_source,
                                                'Vector String': cvss_v30_vectorString,
                                                'CVSS Version': "3.0",
                                                'Severity': cvss_v30_severity,
                                                'Base Score': cvss_v30_base_score
                                            })
                            
                        
                    if 'cvssMetricV31' in cve['cve']['metrics']:
                        for metric in cve['cve']['metrics']['cvssMetricV31']:
                            cvss_v31_source = metric.get('source', "")
                            cvss_v31_type = metric.get('type', "")
                            cvss_v31 = metric.get('cvssData', {})
                            if cvss_v31:
                                cvss_v31_base_score = cvss_v31.get('baseScore', 0)
                                cvss_v31_severity = cvss_v31.get('baseSeverity', "")
                                cvss_v31_vectorString = cvss_v31.get('vectorString', "")
                                all_cves.append({
                                                'Component Name': keyword,
                                                'CVE ID': cve_id,
                                                'Descriptions': description,
                                                'Type': cvss_v31_type,
                                                'Source': cvss_v31_source,
                                                'Vector String': cvss_v31_vectorString,
                                                'CVSS Version': "3.1",
                                                'Severity': cvss_v31_severity,
                                                'Base Score': cvss_v31_base_score
                                             })
                    


                if len(cves) < 200:
                    print("Less than 200 CVEs found, breaking the loop.")
                    break
                params['startIndex'] += 2000

            else:
                print(f"{red}** No CVE data found for this {keyword}{reset}.")
                break

        elif response.status_code == 403:
            logger.warning(f"{red}*** Received 403 error. Sleeping for 30 seconds and retrying...{reset}")
            time.sleep(30)
            continue  # Retry the same request after sleep
        else:
            logger.error(f"{red}** Failed to retrieve data for {keyword}. HTTP Status Code: {response.status_code}{reset}")
            break

    return all_cves

def process_excel(product_df, repo_file, get_components_file, nvd_with_no_severity_file,actual_missing_data_file,severities, api_key):
    ''' 
    Processing the Component file
    '''
    start_time = time.time()
    start_timestamp = datetime.now()
    st.sidebar.success("Extraction Data is procressing...")
    print(f"Script started at: {start_timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    print("---------------------------------------------")
    
    product_df = product_df.head(60)
    

    product_df.to_excel("json_output.xlsx")

    print("*** Step 1st Json to Excel Started") 

    if os.path.exists(get_components_file):
            os.remove(get_components_file)
            print(f"deleted existing file: {get_components_file}")
            print("---------------------------------------------")
    else:
        print(f"File does not exist: {get_components_file}. Skipping deletion.")
    
    if os.path.exists(nvd_with_no_severity_file):
        os.remove(nvd_with_no_severity_file)
        print(f"deleted existing file: {nvd_with_no_severity_file}")
        print("---------------------------------------------")
    else:
        print(f"File does not exist: {nvd_with_no_severity_file}. Skipping deletion.")

    if os.path.exists(actual_missing_data_file):
        os.remove(actual_missing_data_file)
        print(f"deleted existing file: {actual_missing_data_file}")
        print("---------------------------------------------")
    else:
        print(f"File does not exist: {actual_missing_data_file}. Skipping deletion.")
    
    df,df2 = merge_product_component(product_df,repo_file)
    print("*** Step 2 product and component dataframe merged")

    print(f"Excel data read successfully. Number of components: {len(df)}")
    print("---------------------------------------------")
   
    if 'Product Name' not in df.columns or 'Component Name' not in df.columns:
        print("Required columns ('Product Name' or 'Component Name') are missing in the input file.")
        print("---------------------------------------------")
        return pd.DataFrame()
    
    df['Query Name'] = df['Component Name'].fillna(df['Product Name']).map(lambda x: x.replace("®", "").replace("  ", " "))  # Use Component Name if available, else Product Name
    unique_queries = df['Query Name'].drop_duplicates().tolist()
    print(f"Number of unique queries to fetch: {len(unique_queries)}")
    st.sidebar.success(f"Number of unique queries to fetch: {len(unique_queries)}")

    all_cve_data = []
    missing_components = []
    processed_queries = set()  # To track already processed queries
    
    max_components_to_process = 30
    total_components = len(unique_queries)
    print(total_components)
    st.sidebar.success("No of total component:{}".format(total_components))
    
    
    progress_bar = st.progress(0,"CVE Search in process..")
    for idx, query_name in enumerate(unique_queries):
        # # Break the loop if we have processed the first 5 components
        if idx >= total_components:
            print(f"Processed {total_components} components, stopping further execution.")
            break
        if query_name in processed_queries:
            continue  # Skip already processed queries
        component_found = False
        print(f"* Processing query {idx + 1}/{total_components}: {cyan}{query_name}{reset}")
        print("---------------------------------------------")
        progress_bar.progress(idx + 1)
    
        # Fetch HIGH and CRITICAL CVE data
        for severity in severities:
            print(f"{yellow}Fetching {severity} severity CVEs for component --> {query_name}{reset}")
            print("---------------------------------------------")
            
            severity_cve_data = search_nvd(query_name, severity, api_key)
            if severity_cve_data:
                print(f"{green}Found {len(severity_cve_data)} CVE IDs for severity {severity}.{reset}")
                print("---------------------------------------------")
                all_cve_data.extend(severity_cve_data)
                component_found = True  # Mark as found if data is returned
            
        if component_found:
        # Append query_name and corresponding file names to file2 if not already present
            matching_rows = df[df['Query Name'] == query_name]

            for _, row in matching_rows.iterrows():
                file_name = row['File Name']
                component_name = row['Query Name']

                # Check if file name already exists in file2
                if file_name not in df2['File Name'].values:
                    # Append new entry to file2
                    new_row = pd.DataFrame({'File Name': [file_name], 'Component Name': [component_name]})
                    df2 = pd.concat([df2, new_row], ignore_index=True)
    
    
        else:
            # Add all rows corresponding to the missing query
            matching_rows = df[df['Query Name'] == query_name].to_dict('records')
            missing_components.extend(matching_rows)
            print(f"{query_name} not found in NVD database.")
            print("---------------------------------------------")

        processed_queries.add(query_name)
    
    st.sidebar.success('Severity Analysis on Missing Data Procressing...')

    # Save missing components to Excel
    if missing_components:
        missing_df = pd.DataFrame(missing_components).drop_duplicates(subset=['Module', 'File Name'])

        nvd_with_no_severity, actual_missing_data = fetch_from_backup_url(missing_df, api_key)

        
        # Save results to separate files
        if nvd_with_no_severity:
            pd.DataFrame(nvd_with_no_severity).to_excel(nvd_with_no_severity_file, index=False, engine='openpyxl')
            print(f"{green}NVD components without severity saved to {nvd_with_no_severity_file}{reset}.")
            

        if actual_missing_data:
            pd.DataFrame(actual_missing_data).to_excel(actual_missing_data_file, index=False, engine='openpyxl')
            print(f"{green}Actual missing components saved to {actual_missing_data_file}.{reset}")
                    
    else:
        missing_df = pd.DataFrame()
        print("No missing components found. Missing components file not created.")
    print("---------------------------------------------")

    df2.drop_duplicates(subset=['File Name'], inplace=True)  # Ensure file names are unique
    df2.to_excel(repo_file, index=False, engine='openpyxl')  # Overwrite the existing file2
    print(f"{green}Updated file2 saved to {repo_file}{reset}")
    print("---------------------------------------------")
    
    if all_cve_data:
        cve_df = pd.DataFrame(all_cve_data)
        output_file_name = get_components_file
        cve_df.to_excel(output_file_name, index=False, engine='openpyxl')
        print(f"{green}Data saved to {output_file_name}{reset}")
        print("---------------------------------------------")
        print("---------------------------------------------")
    else:
        print("No CVE data collected. Output file not created.")
        cve_df = pd.DataFrame()

    end_time = time.time()
    end_timestamp = datetime.now()
    total_time = timedelta(seconds=(end_time - start_time))

    print(f"Script ended at: {end_timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total processing time: {total_time}")
    print("------XXXX------XXXX---------XXXXXX-----")
    
    st.sidebar.success("Data is Extracted , Sentiment Analysis Started..")

    return cve_df
    

def CVE_Extraction(data, repo_file, api_key, get_components_file ,nvd_with_no_severity_file,actual_missing_data_file):
    '''
    calling function
    '''
    severities = ["HIGH", "CRITICAL"]
    
    cve_df = process_excel(data, repo_file, get_components_file,nvd_with_no_severity_file,actual_missing_data_file ,severities, api_key)
    
    return cve_df 


def fetch_from_backup_url(missing_df, api_key):
    """ Fetch data from NVD using the keyword-only URL for components in the missing DataFrame. """
    url_base = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="
    nvd_with_no_severity = []  # To store components found on NVD without severity
    actual_missing_data = []   # To store components not found at all on NVD
    missing_df['Query Name'] = missing_df['Component Name'].fillna(missing_df['Product Name']).map(lambda x: x.replace("®", "").replace("  ", " "))
    print(missing_df['Query Name'].head(10))  # Use Component Name if available, else Product Name

    for _, row in missing_df.iterrows():
        keyword = row['Query Name']
        url = f"{url_base}{keyword}"
        headers = {'Authorization': f'Bearer {api_key}'}
        print(url)
        session = requests.Session()
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        max_retries = 3
        for attempt in range(max_retries):
            print(f"Attempt {attempt + 1} of {max_retries}")
            try:
                response = session.get(url, headers=headers)
                if response.status_code == 403:
                    logger.warning(f"{red}*** Received 403 error. Sleeping for 30 seconds and retrying...{reset}")
                    time.sleep(30)
                    continue  # Retry the same request after sleep
                break  # Exit the loop if successful
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError) as e:
                    print(f"*** Connection error encountered: {e}. Attempt {attempt + 1} of {max_retries}.")
                # Retry logic with a maximum of 3 attempts
            if attempt < max_retries - 1:
                print("Retrying...")
                time.sleep(30)  # Wait for 30 seconds before retrying
            else:
                print("Max retries reached. Moving to the next component.")
                time.sleep(30)
                continue  # Retry the same request after sleep

        print(f"Fetching data for keyword: {keyword}")

        if response.status_code == 200:
            data = response.json()
            print(data)
            if 'vulnerabilities' in data and data['vulnerabilities']:
                # Found on NVD but lacks severity
                print(f"Data found on NVD for {keyword} without severity.")
                nvd_with_no_severity.append(row)
            else:
                # No data found even on backup URL
                print(f"No data found on NVD for {keyword}.")
                actual_missing_data.append(row)
                print("actual data is appending")

        else:
            logger.error(f"{red}** Failed to retrieve data for {keyword}. HTTP Status Code: {response.status_code}{reset}")
            break

    return nvd_with_no_severity, actual_missing_data


# missing_component_data = "Data/Component_Data.xlsx"
# repo_file = "Data/Component_Data.xlsx"
# get_components_file = 'Results/Temp/Component_File.xlsx'
# nvd_with_no_severity_file = 'Results/Temp/NVD_with_No_Severity.xlsx'
# actual_missing_data_file = 'Results/Temp/Actual_missing_Data.xlsx'
# api_key = "b8a78be9-2c47-4646-92e8-c2ef8247a40a"
# source_path = "Results/Temp"
# destination_path = "Results/Temp"
# cve_file_path = "Results/Final/Final_CVE_Data.xlsx"
# nvd_file_path = "Results/Final/Final_NVD_Data.xlsx"
# sen_file_path = "Results/Final/Final_SEN_Data.xlsx"
# severities = ["HIGH", "CRITICAL"]

# product_df = pd.read_excel("/Users/aplynek/Documents/Infra_code/Actual_missing_Data.xlsx")
# process_excel(product_df, repo_file, get_components_file, nvd_with_no_severity_file,actual_missing_data_file,severities, api_key)