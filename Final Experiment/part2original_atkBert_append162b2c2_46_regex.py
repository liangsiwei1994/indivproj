import os
import json
from scipy import spatial
from sentence_transformers import SentenceTransformer
import pandas as pd
import nltk
import argparse
import re

bert_model = SentenceTransformer('basel/ATTACK-BERT')

df = pd.read_csv('/homes/sl222/Documents/individual_proj/IEEEEuroSP23/attack_pattern/enterprise-techniques-with-procedureV2-3.csv')

patterns = {
    "URL": [
        re.compile("\\b([a-z]{3,}\\:\\/\\/[\\S]{16,})\\b", re.IGNORECASE)
    ],
    "IP":[
        re.compile("\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b", re.IGNORECASE)
    ],
    "IP2":[
        re.compile("\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\[\\.\\]\\d{1,3})\\b", re.IGNORECASE)
    ],
    "E-mail": [
        re.compile("\\b([a-z][_a-z0-9-.]+@[a-z0-9-]+\\.[a-z]+)\\b", re.IGNORECASE)
    ],

    "DocumentFile": [
        re.compile("\\b([a-z0-9-_\\.]+\\.(sys|htm|html|jpg|png|vb|scr|pif|chm|zip|rar|cab|pdf|doc|docx|ppt|pptx|xls|xlsx|swf|gif))\\b", re.IGNORECASE)
    ],
    "ExecutableFile": [
        re.compile("\\b([a-z0-9-_\\.]+\\.(exe|dll|jar|bat|ps1|js))\\b", re.IGNORECASE)
    ],
    "ExecutableFile2": [
        re.compile("\\b([a-z0-9-_\\.]*\\.(exe|dll|jar|bat|ps1|js))(\\b|$)", re.IGNORECASE)
    ],
    "MD5": [
        re.compile("\\b([a-f0-9]{32})\\b", re.IGNORECASE)
    ],
    "SHA1": [
        re.compile("\\b([a-f0-9]{40})\\b", re.IGNORECASE)
    ],
    "SHA256": [
        re.compile("\\b([a-f0-9]{64})\\b", re.IGNORECASE)
    ],

    "FilePath": [
        re.compile("\\b[a-z]:\\\\{1,2}[a-z0-9-_\\.\\\\]+(?=\\s|$)", re.IGNORECASE),
        re.compile("[~]*/[a-z0-9-_\\./]{2,}(?=[%a-z0-9]*\\\\[a-z0-9-_\\.\\\\%]+(?=\\s|$))", re.IGNORECASE)
    ],
    "FilePath2": [
        re.compile("\\b[a-zA-Z]:\\\\{1,2}[a-zA-Z0-9-_\\.\\\\]+(?=\\s|$)", re.IGNORECASE),
        re.compile("\\b[a-z]:\\\\{1,2}[a-z0-9-_\\.\\\\]+(?=[\\s,]|$)", re.IGNORECASE)

    ],

    "Registry": [
        re.compile("\\b((kcu|hklm|hkcu|hkey_local_machine|hkey_current_user|software).{0,1}\\\\[\\\\a-z0-9-_]+)\\b", re.IGNORECASE),
        re.compile("\\b((hklm|hkcu|hkey_local_machine|hku)\\\\\\\\[\\\\\\\\a-z0-9-_]+)\\b", re.IGNORECASE)
    ],
    
    "Vulnerability": [
        # re.compile("\\b(cve\\-[0-9]{4}\\-[0-9]{4,6})\\b", re.IGNORECASE),
        re.compile("\\b(cve[-\\s][0-9]{4}[-\\s][0-9]{4,6})\\b", re.IGNORECASE)
    ],
    # "Arguments": [
    #     re.compile("\\s[-/\\\\][0-9a-z]+\\s", re.IGNORECASE)
    # ],
    "URL2": [
        re.compile("\\b((http|https)://)?([A-Za-z0-9\\-\\.]+|\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\[\\.\\][A-Za-z]{2,}(:[0-9]+)?(/\\S*)?\\b", re.IGNORECASE)
    ]
}

# Replacement words for each pattern
replacements = {
    "URL": "url",
    "URL2": "url",
    "Host": "host",
    "IP": "host",
    "IP2": "host",
    "E-mail": "email",

    "DocumentFile": "document",
    "ExecutableFile": "executable",
    "ExecutableFile2": "executable",

    "MD5": "file",
    "SHA1": "file",
    "SHA256": "file",

    "FilePath": "path",
    "FilePath2": "path",

    "Registry": "registry",

    "Vulnerability": "vulnerability",
    # "Arguments": " "
}

attack_pattern_dict = {} 
technique_mapping = {}

prev_id = None

for _, row in df.iterrows():
    _id = row['ID']
    if not pd.isnull(_id):
        if _id in attack_pattern_dict:
            attack_pattern_dict[_id].append([row['Name'], row['Description'], row['Procedure']])
            technique_mapping[row['Name']] = prev_id
        else:
            attack_pattern_dict[_id] = [[row['Name'], row['Description'], row['Procedure']]]
            prev_id = _id
            technique_mapping[row['Name']] = _id
    else:
        attack_pattern_dict[prev_id].append([row['Name'], row['Description'], row['Procedure']])
        technique_mapping[row['Name']] = prev_id

embedding_memo = {}

def get_embedding(txt, txt_type):
    if txt_type == "attack_phrase":
        if txt in embedding_memo:
            return embedding_memo[txt]
        emb = bert_model.encode([txt])[0]
        embedding_memo[txt] = emb
        return emb
    
    if txt_type == "name":
        if txt in embedding_memo:
            return embedding_memo[txt]
        
        # # Filter rows where column 'A' has the value 'cherry'
        # index = (df['Name'] == txt).idxmax()
        # # Use the found index to get the value from column B
        # value = df.loc[index, 'Name_embedding']

        value = bert_model.encode([txt])[0]

        embedding_memo[txt] = value
        return value

    if txt_type == "description":
        if txt in embedding_memo:
            return embedding_memo[txt]
        
        # # Filter rows where column 'A' has the value 'cherry'
        # index = (df['Description'] == txt).idxmax()
        # # Use the found index to get the value from column B
        # value = df.loc[index, 'Description_embedding']

        value = bert_model.encode([txt])[0]

        embedding_memo[txt] = value
        return value

    if txt_type == "procedure":
        if txt in embedding_memo:
            return embedding_memo[txt]
        #  # Filter rows where column 'A' has the value 'cherry'
        # index = (df['Procedure'] == txt).idxmax()
        # # Use the found index to get the value from column B
        # value = df.loc[index, 'Procedure_embedding']

        value = bert_model.encode([txt])[0]

        embedding_memo[txt] = value
        return value

def get_embedding_distance(txt1, txt2, txt2_type):

    for pattern_name, pattern_list in patterns.items():
        for pattern in pattern_list:
            txt2 = pattern.sub(replacements[pattern_name], txt2)

    p1 = get_embedding(txt1, "attack_phrase")
    p2 = get_embedding(txt2, txt2_type)
    score = spatial.distance.cosine(p1, p2)
    return score, txt2

description_distance = {}

def get_mitre_id(phrase, text):
    min_dist = 25
    ret = None
    for k, tech_list in attack_pattern_dict.items():
        for v in tech_list:
            # v[0] -> attack pattern title, v[1] -> description
            score1, txt1 = get_embedding_distance(text, v[1], "description")
            score2, txt2 = get_embedding_distance(phrase, v[1], "description")
            if pd.isnull(v[2]):
                d = 0.4*score1 + 0.6*score2
                min_txt = txt1
            else:
                score3, txt3 = get_embedding_distance(text, v[2], "procedure")
                score4, txt4 = get_embedding_distance(phrase, v[2], "procedure")
                d = 0.4*score3 + 0.6*score4
                description_score = 0.4*score1 + 0.6*score2
                if description_score < d:
                    d = description_score
                    min_txt = txt1
                else:
                    min_txt = txt3
            if d < min_dist:
                min_dist = d
                ret = k
                match_proc = min_txt
    return ret, min_dist, match_proc

def remove_consec_newline(s):
    ret = s[0]
    for x in s[1:]:
        if not (x == ret[-1] and ret[-1]=='\n'):
            ret += x
    return ret

def get_all_attack_patterns(fname, th=0.6):
    mapped = {}
    with open(fname, 'r', encoding='utf-8') as f:
        text = f.read()
    
    text = remove_consec_newline(text)
    text = text.replace('\t', ' ')
    text = text.replace("\'", "'")
    # sents_nltk = nltk.sent_tokenize(text)
    sents_nltk = re.split('\n', text)
    sents = []
    phrases = []

    sentence = True
    for x in sents_nltk:
        # sents += x.split('\n')
        sentences = re.split('\n', x)
        if len(sentences) > 0:
            if sentence:
                for i, sent in enumerate(sentences):
                    if i % 2 == 0:
                        sents.append(sent)
                        sentence = False
                    else:
                        phrases.append(sent)
                        sentence = True
            else:
                for i, sent in enumerate(sentences):
                    if i % 2 == 0:
                        phrases.append(sent)
                        sentence = True
                    else:
                        sents.append(sent)

    for i, line in enumerate(sents):
        if len(line) > 0:
            # print(phrases[i])
            _id, dist, match_proc_found = get_mitre_id(phrases[i], line)
            if dist < th:
                if _id not in mapped:
                    mapped[_id] = dist, line+"xxxxx"+match_proc_found
                else:
                    if dist < mapped[_id][0]:
                        mapped[_id] = mapped[_id] = dist, line+"xxxxx"+match_proc_found
    # print("returning")
    return mapped

parser = argparse.ArgumentParser(description='Process input file.')
parser.add_argument('--sentence_file', type=str, help='file that contains the string to analyze')
args = parser.parse_args()

ret = get_all_attack_patterns(args.sentence_file, th=0.6)

for k, v in ret.items():
    print(k, v, attack_pattern_dict[k][0][0])