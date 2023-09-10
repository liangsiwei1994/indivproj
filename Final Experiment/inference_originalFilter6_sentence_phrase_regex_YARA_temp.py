import torch
import nltk
import os
import re
import string
import spacy
import pandas as pd

from argparser import parse_inference_arguments as parse_args
from models import EntityRecognition, SentenceClassificationBERT, SentenceClassificationRoBERTa
from config import *

nlp = spacy.load("en_core_web_sm")

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

YARA_pattern = re.compile(r'^\s*(\$[a-zA-Z0-9_]+)\s*=\s*"([^"\\]*(\\.[^"\\]*)*)".*$')

nlp = spacy.load("en_core_web_sm")

def has_vo_ov_relation(doc):
    pairs = []
    
    for token in doc:
        # Check for verb-object relationship
        if token.pos_ == "VERB" and token.text.isalpha() and any(child.dep_ == "dobj" for child in token.children):
            for child in token.children:
                if child.dep_ == "dobj":
                    pairs.append((token, child))

        # Check for object-verb relationship
        if token.pos_ == "NOUN":
            for child in token.head.children:
                if child.dep_ in ["nsubj", "nsubjpass"] and token.head.text.isalpha():
                    pairs.append((token.head, token))
                    
        # Check for object-verb relationship
        if token.pos_ == "PROPN":
            for child in token.head.children:
                if child.dep_ in ["nsubj", "nsubjpass"] and token.head.text.isalpha():
                    pairs.append((token.head, token))

                    
        # Check for object-verb relationship
        if token.pos_ == "PRON":
            for child in token.head.children:
                if child.dep_ in ["nsubj", "nsubjpass"] and token.head.text.isalpha():
                    pairs.append((token.head, token))
    
    return pairs

def check_VO_OV_pairs_outside_quotes(text):
    doc = nlp(text)
    pairs = has_vo_ov_relation(doc)
    
    # If no pairs are found, return False
    if not pairs:
        return False

    # Extract all the quoted texts
    quoted_texts = []
    for quote in ['"', "'"]:
        start_indices = [i for i, char in enumerate(text) if char == quote]
        for i in range(0, len(start_indices), 2):  # considering pairs of quotes
            if i + 1 < len(start_indices):
                quoted_texts.append(text[start_indices[i]:start_indices[i + 1] + 1])

    # Check if any pair falls entirely inside a quoted text
    for pair in pairs:
        word1_in_any_quote = any(pair[0].text in quote for quote in quoted_texts)
        word2_in_any_quote = any(pair[1].text in quote for quote in quoted_texts)
    
        # If either word is not inside any of the quoted_texts
        if not word1_in_any_quote or not word2_in_any_quote:
            return True
        
    # print("here")
    return False


def valid_string_check(sentence):
    words = sentence.split()
    first_word = words[0] if words else ""
    if first_word:
        count = sum(1 for word in words if word[0].isupper() or word[0].isdigit() or word[0] in string.punctuation)
        percentage = count / len(words) * 100
        if percentage > 50:
            print('here')
            return False
        else:
            return True
    return False

#Return True if sentence is not a CLI command
def check_if_not_CLI(sentence):
    # List of common CLI commands
    cli_commands = ["path", "cd", "mkdir", "wmic", "ls", "cat", "mv", "cp", "rm", "grep", 
                    "ping", "ifconfig", "ipconfig", "netstat", "ps", "pwd", "sudo", "find", 
                    "ssh", "ftp", "sftp", "telnet", "nslookup", "curl", "wget", "whoami", 
                    "chmod", "chown", "apt-get", "yum", "tar", "kill", "powershell", "echo"]

    all_words = sentence.split()
    first_word= all_words[0]
    
    if first_word in cli_commands:
        return False
    return True

#return true if it's not a suspected html command, i.e. not a case where first word starts with '<' AND last word ends with '>'
def is_not_html_line(sentence):
    words = sentence.split()

    if not words:  # if the sentence is empty
        # print('here')
        return False

    first_word = words[0]
    last_word = words[-1]
    return not (first_word.startswith('<') and last_word.endswith('>'))

def not_yara_rule(s):
    return not bool(YARA_pattern.match(s))

def overall_check(sentence):
    if check_VO_OV_pairs_outside_quotes(sentence) and valid_string_check(sentence) and is_not_html_line(sentence) and check_if_not_CLI(sentence) and not_yara_rule(sentence):
        return True
    return False








def remove_consec_newline(s):
    ret = s[0]
    for x in s[1:]:
        if not (x == ret[-1] and ret[-1]=='\n'):
            ret += x
    return ret

def extract_sentences(text):
    text = remove_consec_newline(text)
    text = text.replace('\t', ' ')
    text = text.replace("\'", "'")

    for pattern_name, pattern_list in patterns.items():
        for pattern in pattern_list:
            text = pattern.sub(replacements[pattern_name], text)

    sents_nltk = nltk.sent_tokenize(text)
    sents = []
    for x in sents_nltk:
        sents += x.split('\n')
    return sents


def classify_sent(sent, model, tokenizer, token_style, sequence_len, device):
    start_token = TOKENS[token_style]['START_SEQ']
    end_token = TOKENS[token_style]['END_SEQ']
    pad_token = TOKENS[token_style]['PAD']
    pad_idx = TOKEN_IDX[token_style]['PAD']

    tokens_text = tokenizer.tokenize(sent)
    tokens = [start_token] + tokens_text + [end_token]

    if len(tokens) < sequence_len:
        tokens = tokens + [pad_token for _ in range(sequence_len - len(tokens))]
    else:
        tokens = tokens[:sequence_len - 1] + [end_token]

    tokens_ids = tokenizer.convert_tokens_to_ids(tokens)
    x = torch.tensor(tokens_ids).reshape(1, -1).reshape(1, -1)
    att = (x != pad_idx).long()

    x, att = x.to(device), att.to(device)

    with torch.no_grad():
        y_pred = model(x, att)
        if torch.argmax(y_pred).item():
            print(sent)
            if overall_check(sent):
                return True
        else:
            return False


def extract_entities(sent, model, tokenizer, token_style, sequence_len, device):
    words_original_case = nltk.word_tokenize(sent)
    words = [x.lower() for x in words_original_case]
    token_to_word_mapping = {}

    word_pos = 0
    x = [TOKEN_IDX[token_style]['START_SEQ']]
    while word_pos < len(words):
        tokens = tokenizer.tokenize(words[word_pos])

        if len(tokens) + len(x) >= sequence_len:
            break
        else:
            for i in range(len(tokens) - 1):
                x.append(tokenizer.convert_tokens_to_ids(tokens[i]))
            x.append(tokenizer.convert_tokens_to_ids(tokens[-1]))
            token_to_word_mapping[len(x) - 1] = words_original_case[word_pos]
            word_pos += 1
    x.append(TOKEN_IDX[token_style]['END_SEQ'])
    if len(x) < sequence_len:
        x = x + [TOKEN_IDX[token_style]['PAD'] for _ in range(sequence_len - len(x))]
    attn_mask = [1 if token != TOKEN_IDX[token_style]['PAD'] else 0 for token in x]

    x = torch.tensor(x).reshape(1, -1)
    attn_mask = torch.tensor(attn_mask).reshape(1, -1)
    x, attn_mask = x.to(device), attn_mask.to(device)

    ret = ''
    cur = ''
    cur_word_count = 0
    with torch.no_grad():
        y_pred = model(x, attn_mask)
        y_pred = y_pred.reshape(-1, y_pred.shape[-1])
        x = x.view(-1)
        for i in range(y_pred.shape[0]):
            if x[i].item() == TOKEN_IDX[token_style]['PAD']:
                break

            token_pred = torch.argmax(y_pred[i]).item()

            # print(tokenizer.convert_ids_to_tokens(x[i].item()), token_pred)

            if i in token_to_word_mapping:
                if token_pred == entity_mapping['ATK']:
                    cur += token_to_word_mapping[i] + ' '
                    cur_word_count += 1
                else:
                    if len(cur) > 0 and cur_word_count >= 2 and is_valid_step(cur):
                        ret += cur[:-1] + '\n'
                        cur = ''
                        cur_word_count = 0
                    else:
                        cur = ''
                        cur_word_count = 0
        if len(cur) > 0 and cur_word_count >= 2:
            ret += cur[:-1] + '\n'
    return ret


def is_valid_step(text):
    verb_codes = {
        'VB',  # Verb, base form
        'VBD',  # Verb, past tense
        'VBG',  # Verb, gerund or present participle
        'VBN',  # Verb, past participle
        'VBP',  # Verb, non-3rd person singular present
        'VBZ',  # Verb, 3rd person singular present
    }
    pos = nltk.pos_tag(nltk.word_tokenize(text))
    for x in pos:
        if x[1] in verb_codes:
            return True
    return False


def infer():
    nltk.download('punkt')
    nltk.download('averaged_perceptron_tagger')

    args = parse_args()

    args.entity_extraction_model = 'roberta-large'
    args.sentence_classification_model = 'roberta-large'

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    
    # print(device)
    
    entity_model = EntityRecognition(args.entity_extraction_model).to(device)
    entity_model.load_state_dict(torch.load(args.entity_extraction_weight, map_location=device))


    if MODELS[args.sentence_classification_model][3] == 'bert':
        sentence_model = SentenceClassificationBERT(args.sentence_classification_model, num_class=2).to(device)
        sentence_model.load_state_dict(torch.load(args.sentence_classification_weight, map_location=device))
    elif MODELS[args.sentence_classification_model][3] == 'roberta':
        sentence_model = SentenceClassificationRoBERTa(args.sentence_classification_model, num_class=2).to(device)
        sentence_model.load_state_dict(torch.load(args.sentence_classification_weight, map_location=device))
    else:
        raise ValueError('Unknown sentence classification model')


    tokenizer_sen = MODELS[args.sentence_classification_model][1]
    token_style_sen = MODELS[args.sentence_classification_model][3]
    tokenizer_sen = tokenizer_sen.from_pretrained(args.sentence_classification_model)
    sequence_len_sen = args.sequence_length_sentence

    tokenizer_ent = MODELS[args.entity_extraction_model][1]
    token_style_ent = MODELS[args.entity_extraction_model][3]
    tokenizer_ent = tokenizer_ent.from_pretrained(args.entity_extraction_model)
    sequence_len_ent = args.sequence_length_entity

    files = os.listdir(args.input_doc)

    for fname in files:
        with open(os.path.join(args.input_doc, fname), 'r', encoding='utf-8') as f:
            text = f.read()       

        sents = extract_sentences(text)
        result = ''
        for x in sents:
            # class 1: attack pattern sentence
            if classify_sent(x, sentence_model, tokenizer_sen, token_style_sen, sequence_len_sen, device):
                ex = extract_entities(x, entity_model, tokenizer_ent, token_style_ent, sequence_len_ent, device)
                # result += ex
                phrases = ex.split('\n')
                sentences = [x + '\n' + phrase for phrase in phrases if any(word.strip() for word in phrase.split())]
                ex = '\n'.join(sentences)
                words = ex.split()
                if not words:
                    continue
                else:
                    result += ex + '\n'
        with open(os.path.join(args.save_path, fname), 'w', encoding='utf-8') as f:
            f.write(result)

if __name__ == '__main__':
    infer()