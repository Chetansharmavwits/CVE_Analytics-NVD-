import pandas as pd
from transformers import pipeline, BartTokenizer
import concurrent.futures
import torch
from tqdm import tqdm
import logging
import json 
from dotenv import load_dotenv
import os 

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
print(f"Device set to use {device}")

classifier = pipeline("zero-shot-classification", model=os.getenv("classify_model"))

tokenizer = BartTokenizer.from_pretrained("facebook/bart-large-mnli")

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
    "read data in the client memory", "read sensitive memory"
]

non_critical_keywords = [
    "denial of service", "crash", "memory consumption", "DoS attacks", "DoS", "application crash", "resource exhaustion"
]

def process_keywords_json(file):
    with open(file, 'r', encoding='utf-8') as file:
        content = json.load(file)
    critical_keywords = content.get("Critical",[])
    non_critical_keywords = content.get("Non-Critical",[])

    return critical_keywords,non_critical_keywords

def contains_critical_keywords(description):
    return any(keyword.lower() in description.lower() for keyword in critical_keywords)

def contains_non_critical_keywords(description):
    return any(keyword.lower() in description.lower() for keyword in non_critical_keywords)

def split_text_into_chunks(text, max_tokens=512):
    """
    Split the text into chunks of a given size based on the token limit.
    """
    # Tokenize the input text
    tokens = tokenizer.encode(text, truncation=False)

    # Split into chunks of max_tokens size
    chunks = [tokens[i:i + max_tokens] for i in range(0, len(tokens), max_tokens)]
    
    # Decode tokens back into text
    chunk_texts = [tokenizer.decode(chunk) for chunk in chunks]
    
    return chunk_texts

def classify_cve(description):
    if contains_critical_keywords(description):
        return "Critical"
    if contains_non_critical_keywords(description) and contains_critical_keywords(description):
        return "Critical"
    if contains_non_critical_keywords(description):
        return "Non-Critical"

    chunks = split_text_into_chunks(description)
    
    # Create context strings for both "Critical" and "Non-Critical"
    critical_context = """This text contains keywords that are typically associated with critical vulnerabilities like code execution, arbitrary code execution, privilege escalation, unauthorized access, local file inclusion, command injection, path/directory traversal, man-in-the-middle attackers to spoof ssl servers, dll hijack, information disclosure, stack buffer overflow, use-after-free vulnerability, cross site scripting, sql injection, impact confidentiality & integrity, server-side request forgery (ssrf), authentication vulnerabilities, xml external entity (xxe) injection, arbitrary memory write, bypass vulnerability, out-of-bounds-arrays, race conditions, file inclusion, heap-based buffer overflow, input validation, malicious executable, command execution, brute force attack, improper neutralization of input, code execution, exposure of sensitive data, access control, data disclosure, sensitive information, read data in the client memory, access control, read sensitive memory"""
    non_critical_context = """This text contains keywords that are typically associated with non-critical vulnerabilities like denial of service, DoS, application crash, crash, memory consumption and resource exhaustion that may cause crashes or denial of service (DoS) attacks."""
    
    critical_scores = []
    non_critical_scores = []
    
    for chunk in chunks:
        candidate_labels_with_context = [
            f"Critical: {critical_context}",
            f"Non-Critical: {non_critical_context}"
        ]
        
        # Perform the zero-shot classification
        result = classifier(chunk, candidate_labels=candidate_labels_with_context)
        print(result['scores'])
        critical_scores.append(result['scores'][0])  # Score for "Critical"
        non_critical_scores.append(result['scores'][1])  # Score for "Non-Critical"
    
    # Aggregate the results (e.g., by majority vote or average score)
    avg_critical_score = sum(critical_scores) / len(critical_scores)
    avg_non_critical_score = sum(non_critical_scores) / len(non_critical_scores)
    
    # Return the classification based on the aggregated scores
    if avg_critical_score > avg_non_critical_score:
        return "Critical"
    else:
        return "Non-Critical"

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

    logger.info("Classification complete!")

    print("Classification complete with parallel processing. ")

    return df

if __name__ == '__main__':
    print("Classification complete with parallel processing. The file is saved as 'classified_cve_descriptions_parallel_with_sematic.xlsx'.")