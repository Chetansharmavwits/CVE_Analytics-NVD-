import pandas as pd
from transformers import pipeline
import concurrent.futures
import torch
from tqdm import tqdm
import logging
from sentence_transformers import SentenceTransformer, util
import json 
from dotenv import load_dotenv
import os 

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
print(f"Device set to use {device}")

classifier = pipeline("zero-shot-classification", model=os.getenv("classify_model"))

model = SentenceTransformer(os.getenv("sentence_model"))

critical_keywords = [
    "remote code execution", "arbitrary code execution", "privilege escalation", 
    "unauthorized access", "local file inclusion", "command injection", 
    "path traversal", "directory traversal","man-in-the-middle attackers to spoof ssl servers", 
    "dll hijack", "information disclosure", "stack buffer overflow", "use-after-free vulnerability", 
    "cross site scripting", "sql injection", "impact confidentiality & integrity", 
    "server-side request forgery (ssrf)", "authentication vulnerabilities", "xml external entity (xxe) injection", 
    "arbitrary memory write", "bypass vulnerability", "out-of-bounds-arrays", "race conditions", 
    "remote file inclusion", "heap-based buffer overflow", "input validation", "malicious executable", 
    "remote command execution", "brute force attack", "improper neutralization of input", "elevation of privilege",
    "exposure of sensitive data", "SQL injection", "arbitrary memory access", "exploits local priv escalation",
    "privilege escalation", "access control", "escalate to admin", "unauthorized access", "data disclosure", 
    "sensitive information", "execute arbitrary code","read arbitrary files","execute arbitrary PHP code",
    "code execution","execute arbitrary files","execute arbitrary Java code", "execute arbitrary commands",
    "read data in the client memory", "read sensitive memory","execute arbitrary"
]

non_critical_keywords = [
    "denial of service", "crash", "memory consumption", "DoS attacks", "DoS"
]
def process_keywords_json(file):
    with open(file, 'r', encoding='utf-8') as file:
        content = json.load(file)
    critical_keywords = content.get("Critical",[])
    non_critical_keywords = content.get("Non-Critical",[])

    return critical_keywords,non_critical_keywords

def contains_critical_keywords_semantic(description):
    # Embed the description and critical keywords
    description_embedding = model.encode(description, convert_to_tensor=True)
    keyword_embeddings = model.encode(critical_keywords, convert_to_tensor=True)

    # Calculate cosine similarities
    cosine_scores = util.pytorch_cos_sim(description_embedding, keyword_embeddings)

    # Check if any similarity score is above a threshold
    if max(cosine_scores[0]) > 0.7:  # You can adjust the threshold
        return True
    return False

def contains_critical_keywords(description):
    return any(keyword.lower() in description.lower() for keyword in critical_keywords)

def contains_non_critical_keywords(description):
    return any(keyword.lower() in description.lower() for keyword in non_critical_keywords)


def classify_cve(description):
    if contains_critical_keywords(description):
        return "Critical"
    if contains_non_critical_keywords(description) and contains_critical_keywords(description):
        return "Critical"
    if contains_non_critical_keywords(description):
        return "Non-Critical"
    if contains_critical_keywords_semantic(description):
        return "Critical"
    
    # Use zero-shot classification as fallback
    result = classifier(description, candidate_labels=["Critical", "Non-Critical"])
    return result['labels'][0]

# Function to process records in parallel
def process_batch(batch):
    return [classify_cve(desc) for desc in tqdm(batch, desc="Processing batch", leave=False)]

def sematic_analysis(df):
    batch_size = 50 
    batches = [df['Descriptions'][i:i + batch_size] for i in range(0, len(df), batch_size)]

    logger.info(f"Total batches to process: {len(batches)}")

    # Use ProcessPoolExecutor (for CPU-bound tasks)
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(tqdm(executor.map(process_batch, batches), total=len(batches), desc="Processing batches"))

    df['Classification'] = [item for sublist in results for item in sublist]

    #df.to_excel('Results/Temp/classified_cve_descriptions_parallel_with_sematic.xlsx', index=False)
    
    return df

if __name__ == '__main__':

    # df = pd.read_excel('CVE Description Data For Sentiment analysis.xlsx')
    # df = df.drop_duplicates()
    # sematic_analysis(df)
    
    # batch_size = 50 
    # batches = [df['Description'][i:i + batch_size] for i in range(0, len(df), batch_size)]

    # logger.info(f"Total batches to process: {len(batches)}")

    # # Use ProcessPoolExecutor (for CPU-bound tasks)
    # with concurrent.futures.ThreadPoolExecutor() as executor:
    #     results = list(tqdm(executor.map(process_batch, batches), total=len(batches), desc="Processing batches"))

    # df['Classification'] = [item for sublist in results for item in sublist]

    # df.to_excel('classified_cve_descriptions_parallel_with_sematic.xlsx', index=False)

    logger.info("Classification complete!")

    print("Classification complete with parallel processing. The file is saved as 'classified_cve_descriptions_parallel_with_sematic.xlsx'.")