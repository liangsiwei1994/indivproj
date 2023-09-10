# Credits: GUI Tkinter code adapted from: https://informatics.indiana.edu/jbollen/I210S10/slides/CH10.ppt
#

import tkinter as tk
from tkinter.scrolledtext import *
from subprocess import run, PIPE
from PIL import Image, ImageTk
from time import sleep
import os
import json
from scipy import spatial
from sentence_transformers import SentenceTransformer
import pandas as pd
import nltk
import argparse
import re

# Functions from other files
from GraphDrawing import *
from getLatestMitre import find_latest_version

# Placed with ATTACK-BERT from mp-net-v2
bert_model = SentenceTransformer('basel/ATTACK-BERT')

df = pd.DataFrame()

# Adapted from https://github.com/li-zhenyuan/Knowledge-enhanced-Attack-Graph/tree/main
# Added regex for examples like 112.112.3[.]3, hello12345678-hacker[.]com, CVE 123-1234
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
embedding_memo = {}

# Adapted from: https://github.com/aiforsec/LADDER/blob/main/notebooks/attack-pattern-extraction.ipynb
# Added capability to use stored embeddings
def get_embedding(txt, txt_type):
     global embedding_memo
     if txt_type == "attack_phrase":
         if txt in embedding_memo:
             return embedding_memo[txt]
         print("EMBEDDING!!!")
         emb = bert_model.encode([txt])[0]
         embedding_memo[txt] = emb
         return emb
     
     if txt_type == "name":
         if txt in embedding_memo:
             return embedding_memo[txt]
         
         # Filter rows where column 'A' has the value 'cherry'
         index = (df['Name'] == txt).idxmax()
         # Use the found index to get the value from column B
         value = df.loc[index, 'Name_embedding']

         # value = bert_model.encode([txt])[0]

         embedding_memo[txt] = value
         return value

     if txt_type == "description":
         if txt in embedding_memo:
             return embedding_memo[txt]
         
         # Filter rows where column 'A' has the value 'cherry'
         index = (df['Description'] == txt).idxmax()
         # Use the found index to get the value from column B
         value = df.loc[index, 'Description_embedding']

         # value = bert_model.encode([txt])[0]

         embedding_memo[txt] = value
         return value

     if txt_type == "procedure":
         if txt in embedding_memo:
             return embedding_memo[txt]
           # Filter rows where column 'A' has the value 'cherry'
         index = (df['Procedure'] == txt).idxmax()
         # Use the found index to get the value from column B
         value = df.loc[index, 'Procedure_embedding']

         # value = bert_model.encode([txt])[0]

         embedding_memo[txt] = value
         return value

# Adapted from: https://github.com/aiforsec/LADDER/blob/main/notebooks/attack-pattern-extraction.ipynb
# Added category argument to find the right embedding
def get_embedding_distance(txt1, txt2, txt2_type):

     p1 = get_embedding(txt1, "attack_phrase")
     p2 = get_embedding(txt2, txt2_type)
     score = spatial.distance.cosine(p1, p2)
     return score, txt2

# Compile the regular expression pattern once
pattern = re.compile(r'\bT\d{4}(?:\.\d{2,3})?\b')

# Return true if TTP index is found in the text, else, return false.
def check_pattern(s):
     
     # Use the compiled pattern to search in the input string
     match = pattern.search(s)
     
     # Return True if a match is found, False otherwise
     return bool(match)

# Adapted from: https://github.com/aiforsec/LADDER/blob/main/notebooks/attack-pattern-extraction.ipynb
# Compares both sentences and phrases
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

# Taken from: https://github.com/aiforsec/LADDER/blob/main/notebooks/attack-pattern-extraction.ipynb
def remove_consec_newline(s):
    ret = s[0]
    for x in s[1:]:
        if not (x == ret[-1] and ret[-1]=='\n'):
            ret += x
    return ret

# Adapted from: # Adapted from: https://github.com/aiforsec/LADDER/blob/main/notebooks/attack-pattern-extraction.ipynb
# Uses both sentences and phrases
def get_all_attack_patterns(fname, th=0.3):

    mapped_all = {}
    mapped = {}
    with open(fname, 'r', encoding='utf-8') as f:
        text = f.read()
         
    if text is None or text == '':
         return None, None
     
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
            _id, dist, match_proc_found = get_mitre_id(phrases[i], line)
            if dist < th:
                if _id not in mapped:
                    mapped[_id] = dist, phrases[i]
                else:
                    if dist < mapped[_id][0]:
                        mapped[_id] = mapped[_id] = dist, phrases[i]
                mapped_all[phrases[i]] = _id, dist
    return mapped, mapped_all
 
    
 
# Adapted from: https://github.com/aiforsec/LADDER/blob/main/notebooks/attack-pattern-extraction.ipynb
# Can handle null and return every phrase with matches
def part2trial(version, threshold=0.3):
    global df
    file_name = version+'.pkl'
    df = pd.read_pickle(file_name)
    
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
            
    ret, ret2 = get_all_attack_patterns('samples/1_predict.txt', th=threshold)

    substrings = []
    labels = []
    scores = []
    tech_name = []
    
    all_substrings = []
    all_labels = []
    all_scores = []

    if ret is None:
        return None, None, None, None, None, None, None
    for k, v in ret.items():
        print(k, v, attack_pattern_dict[k][0][0])
        substrings.append(v[1])
        labels.append(k)
        scores.append(str(v[0]))
        tech_name.append(attack_pattern_dict[k][0][0])
        
    for k, v in ret2.items():
        all_substrings.append(k)
        all_labels.append(v[0])
        all_scores.append(v[1])
        
    return substrings, labels, scores, tech_name, all_substrings, all_labels, all_scores

######################################################################
# Anything above there infer from the attack phrases extracted!
######################################################################
















######################################################################
# This portion collect the files available for reference!
######################################################################

# Regular expression pattern to match filenames of the form "vxx.xx"
pattern = re.compile(r'^v(\d+\.\d+)\.pkl$')
    
def get_matching_files(directory):
    """Returns a list of file names in the directory matching the pattern 'vxx.xx'."""
    
    # List all files and directories in the directory
    all_entries = os.listdir(directory)

    # Filter out directories and filenames that don't match the compiled pattern
    matching_files = [pattern.match(entry).group(1) for entry in all_entries if os.path.isfile(os.path.join(directory, entry)) and pattern.match(entry)]
    
    # Sort the files based on the float value after the 'v'
    matching_files.sort(key=lambda x: float(x), reverse=True)

    return ["v" + file for file in matching_files]















######################################################################
# This portion is the App!
######################################################################

# GUI app is adapted from the tutorial: https://informatics.indiana.edu/jbollen/I210S10/slides/CH10.ppt
class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.grid(sticky='nsew')
        self.create_widgets()


    def create_widgets(self):
        
        self.custom_font = ("Arial", 12)
        self.custom_font_bold = ("Arial", 12, "bold")
        
        
        # Create a frame for the top part of the GUI
        top_frame = tk.Frame(self)
        top_frame.grid(row=0, column=0, columnspan=2, sticky='nsew')
    
        # Text Label
        self.label = tk.Label(top_frame, text="Copy and Paste CTI Report Here", font = self.custom_font_bold)
        self.label.pack(padx=20, pady=(5,0))
        # self.label.grid(row=0, column=0, padx=0, pady=1, columnspan=2, sticky='nsew')
        # self.label.grid(row=0, column=0, padx=20, pady=(5, 0), sticky='nsew')

        # Text Entry
        # self.entry = tk.Entry(top_frame)
        self.entry = tk.Text(top_frame, width=80, height=15, wrap=tk.WORD, font=self.custom_font)
        self.entry.pack(padx=20, pady=5)
        
        
        
        
    
        # Subframe for Process Button, Dropdown, its label and the Threshold input
        process_dropdown_frame = tk.Frame(top_frame)
        process_dropdown_frame.pack(padx=25, pady=5)
    
        # Label for the Dropdown (OptionMenu) inside the subframe
        self.dropdown_label = tk.Label(process_dropdown_frame, text="Select a MITRE reference file:")
        self.dropdown_label.pack(side="left", padx=(25, 0))
    
        # Dropdown (OptionMenu) inside the subframe
        self.selected_option = tk.StringVar(self)
        matching_files_list = get_matching_files(os.getcwd())
        matching_files_list.append("Update")
        
        if not matching_files_list:
            matching_files_list.append("No MITRE reference .pkl file found")
        self.selected_option.set(matching_files_list[0]) 
        self.dropdown = tk.OptionMenu(process_dropdown_frame, self.selected_option, *matching_files_list)
        self.dropdown.pack(side="left", padx=(0, 50))
        
        # Process Button inside the subframe
        self.process_button = tk.Button(process_dropdown_frame, text="PROCESS", command=self.run_script)
        self.process_button.pack(side="left", padx=(25, 25))
    
        # Label and Entry for Threshold
        self.threshold_label = tk.Label(process_dropdown_frame, text="Cosine Distance Score Threshold (insert a value between 0 to 1):")
        self.threshold_label.pack(side="left", padx=(25, 0))
        self.threshold_entry = tk.Entry(process_dropdown_frame, width=5)
        self.threshold_entry.insert(0, "0.3") 
        self.threshold_entry.pack(side="left", padx=0)
        
        # Create a label beside the button but don't display it yet
        self.img_label = tk.Label(self, text="Display sequence of TTP appearance in the text \n (Use only if CTI Report talks about a single attack campaign chronologically): ")
        # Create the Show Image Button but don't display it yet
        self.show_img_button = tk.Button(self, text="Show TTP Appearance Sequence of Latest Run", command=lambda: self.show_image_popup("file.png"))
        

        
        
        
        # Configure the grid to expand contents
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=0) # set weight to zero to reduce the gap between buttons and output!!
        self.grid_rowconfigure(1, weight=0) 
        self.grid_rowconfigure(2, weight=1) 
        # self.grid_rowconfigure(3, weight=1) 
        
    
        top_frame.grid_columnconfigure(0, weight=1)
        top_frame.grid_rowconfigure(0, weight=1)
        
 
         # Configure the grid to expand contents
        self.grid_columnconfigure(0, weight=50)  # Text Output Box
        self.grid_columnconfigure(1, weight=50)  # Image
        
        
    ######################################################################
    # This function runs the inference part!!!!
    ######################################################################
    @staticmethod    
    def get_long_string_from_script():
        entity_extraction_weight_value = 'models/entity_ext.pt'
        sentence_classification_weight_value = 'models/sent_cls.pt'
        command = [
            'python',
            'inference_final.py',
            '--entity-extraction-weight', entity_extraction_weight_value,
            '--sentence-classification-weight', sentence_classification_weight_value
        ]
        result = run(command, stdout=PIPE, stderr=PIPE, text=True)
        if result.returncode == 0:
            print(result.stdout)
            return result.stdout
        else:
            raise Exception(f"Error executing first script: {result.stderr}")
    ######################################################################
    # UP TO HERE: COLLECT THE "PRINTED" VALUES USING THE STDOUT = PIPE
    ######################################################################    
        
            
    def save_to_file(self, content, filename='user_input.txt'):
        with open(filename, 'w') as file:
            file.write(content)

    def run_script(self):
        user_input = self.entry.get("1.0", 'end-1c')
        
        self.save_to_file(user_input, 'samples/1.txt')
        
        # long_string = """In February 2022, the threat actors exploited Log4Shell for initial access to the organization’s unpatched VMware Horizon server. As part of their initial exploitation, CISA observed a connection to known malicious IP address host lasting 17.6 seconds. 
        # The actors’ exploit payload ran the following PowerShell command that added an exclusion rule to Windows Defender: """
        
        # Get the long string from the first script
        long_string = Application.get_long_string_from_script()
        
        # Get the substrings and labels from the second script
        selected_version = self.selected_option.get()
        # selected_version = "v13.1"
        
        if selected_version == "Update":
            # Find the latest version based on mitre's commit
            # Name and owner of MITRE repository: https://github.com/mitre/cti
            owner = "mitre"
            repo_name = "cti" 
            current_latest = float(find_latest_version(owner, repo_name))
            # Read from the file named "latest_version.txt" to see what is the latest version saved
            with open("latest_version_no.txt", "r") as file:
                saved_version_str = file.read().strip()  # for example, "v13.1"
            # Remove the "v" prefix and convert to float
            saved_version_float = float(saved_version_str)
            if current_latest == saved_version_float:
                print("CURRENT DATABASE ALREADY THE LATEST VERSION")
            else:
                print("UPDATING...")
                setup_file_for_reference("v" + str(current_latest))
        
        threshold_value = self.threshold_entry.get()
        substrings, labels, scores, tech_names, all_substrings, all_labels, all_scores = part2trial(selected_version, float(threshold_value))
        
        all_labels_copy = all_labels.copy()
        all_substrings_copy = all_substrings.copy()
        
        attack_lifecycle_mapping(all_labels_copy, all_substrings_copy, version=selected_version)
        
        # print out results
        self.highlight_substrings(long_string, all_substrings, all_labels, all_scores)
        
        # After processing, display the results
        self.display_results(substrings, labels, scores, tech_names)
        
        # Display the label beside the button
        self.img_label.grid(row=3, column=0, pady=5, padx = (200,0) )
        # Display the Show Image Button at the end
        self.show_img_button.grid(row=3, column=1, pady=5, padx = (0, 200))

    def highlight_substrings(self, user_input, substrings, labels, scores):
        self.highlight_label = tk.Label(self, text="Input Text with Identified Techniques", font=self.custom_font_bold)
        self.highlight_label.grid(row=1, column=0, padx=20, pady=(10,0), sticky='nsew')  # Adjust row/column as needed
        self.text_output = tk.Text(self, wrap=tk.WORD, width=40, height=2, font=self.custom_font)
        self.text_output.grid(row=2, column=0, padx=20, pady=5, sticky='nsew')
        
        labelled_position = []
        
        if not substrings or not labels:  # Check if both substrings and labels are empty or None
            self.text_output.insert(tk.END, user_input)  # Simply insert the original text
            return
    
        position = 0  # Maintain a position index for where we are in the user input string
    
        while position < len(user_input):
            # Check if any of the substrings occur at the current position
            for substring, label, score in zip(substrings, labels, scores):
                if user_input.startswith(substring, position) and position not in labelled_position:
                    # Insert the highlighted substring
                    self.text_output.insert(tk.END, substring + ' ', 'highlight')
                    # Insert the label with a space before and after
                    self.text_output.insert(tk.END, '[' + label + ', ' + str(score)[:5] + ']', 'label')
                    # Move the position by the length of the matched substring
                    position += len(substring)
                    # Keep track of duplicate position in case of duplicate substrings
                    labelled_position.append(position)
                    break
                else:
                    # Replace with all the wonky characters due to phrase extraction
                    substring = substring.replace(" ( ", " (")
                    substring = substring.replace(" ) ", ") ")
                    substring = substring.replace(" ’", "’")
                    substring = substring.replace(" , ", ", ")
                    substring = substring.replace(" '", "'")
                    substring = substring.replace("“ ", "“")
                    substring = substring.replace(" ”", "”")
                    substring = substring.replace("`` ", '"')
                    substring = substring.replace(" ''", '"')
                    if user_input.startswith(substring, position) and position not in labelled_position:
                        # Insert the highlighted substring
                        self.text_output.insert(tk.END, substring + ' ', 'highlight')
                        # Insert the label with a space before and after
                        self.text_output.insert(tk.END, '[' + label + ', ' + str(score)[:5] + ']', 'label')
                        # Move the position by the length of the matched substring
                        position += len(substring)
                        # Keep track of duplicate position in case of duplicate substrings
                        labelled_position.append(position)
                        break
                                      
                    else:
                        # Try again on the closed inverted comma in case it's an apostrophe
                        substring = substring.replace("’ ", "’")
                        if user_input.startswith(substring, position) and position not in labelled_position:
                            # Insert the highlighted substring
                            self.text_output.insert(tk.END, substring + ' ', 'highlight')
                            # Insert the label with a space before and after
                            self.text_output.insert(tk.END, '[' + label + ', ' + str(score)[:5] + ']', 'label')
                            # Move the position by the length of the matched substring
                            position += len(substring)
                            # Keep track of duplicate position in case of duplicate substrings
                            labelled_position.append(position)
                            break
                    
            else:
                # If no substring matched, insert one character from the user input without any highlighting
                self.text_output.insert(tk.END, user_input[position])
                # Move to the next character in the user input
                position += 1
                
        self.text_output.tag_config('highlight', foreground='red', font=self.custom_font_bold)
        self.text_output.tag_config('label', foreground='red', background='yellow', font=self.custom_font_bold)
        
    
    def display_results(self, substrings, labels, scores, tech_names):
        # Check if the result_output widget exists, and if so, clear it
        if hasattr(self, 'result_output'):
            self.result_output.destroy()
        
        # Create the result_output Text widget
        self.results_label = tk.Label(self, text="Closest Cosine Distance Phrases for Each Technique", font=self.custom_font_bold)
        self.results_label.grid(row=1, column=1, padx=20, pady=(10,0), sticky='nsew')  # Adjust row/column as needed
        self.result_output = tk.Text(self, wrap=tk.WORD, width=40, height=2, bg='#F5F5F5', font=self.custom_font)
        self.result_output.grid(row=2, column=1, padx=20, pady=5, sticky='nsew')
        
        if not substrings or not labels or not scores or not tech_names:  # Check if both substrings and labels are empty or None
            substring = 'No Phrase'
            label = 'No Labels'
            score = 'No Score'
            tech_name = 'No technique'
            self.result_output.insert(tk.END, f"Substring: {substring}\nLabel: {label}\nTechnique Name: {tech_name}\nScore: {score}\n\n")
            return
        
        # Populate the Text widget with the results
        for substring, label, score, tech_name in zip(substrings, labels, scores, tech_names):
            self.result_output.insert(tk.END, f"MITRE Technique: {label}\nTechnique Name: {tech_name}\nAttack Phrase: {substring}\nScore: {score}\n\n")
    
        # Make the Text widget read-only
        self.result_output.config(state=tk.DISABLED)
        
        
    def show_image_popup(self, image_path):
        """
        Display an image in a scrollable popup window.
    
        Parameters:
        - image_path (str): Path to the image.
        """
        
        # Create a new top-level window
        image_window = tk.Toplevel(self.master)
        image_window.title("Graphical Representation of Sequence of Identified MITRE Techniques")
        
        # Open the image using PIL and convert it to a PhotoImage object
        img = Image.open(image_path)
        photo = ImageTk.PhotoImage(img, master=image_window)  # specify master
        
        # Create a Canvas inside the Toplevel window
        canvas = tk.Canvas(image_window)
        canvas.grid(row=0, column=0, sticky='nsew')  # Adjusted to use grid
    
        # Create scrollbars and attach them to the canvas
        v_scrollbar = tk.Scrollbar(image_window, orient=tk.VERTICAL, command=canvas.yview)
        v_scrollbar.grid(row=0, column=1, sticky='ns')  # Adjusted to use grid
        h_scrollbar = tk.Scrollbar(image_window, orient=tk.HORIZONTAL, command=canvas.xview)
        h_scrollbar.grid(row=1, column=0, sticky='ew')  # Adjusted to use grid
        canvas.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
    
        # Configure row and column weights for the window
        image_window.grid_rowconfigure(0, weight=1)
        image_window.grid_columnconfigure(0, weight=1)
        
        # Add the image to the canvas
        canvas.create_image(0, 0, anchor=tk.NW, image=photo)
        canvas.config(scrollregion=canvas.bbox(tk.ALL))
        
        # Keep a reference to the image to avoid garbage collection
        canvas.image = photo
        
        # Show the window
        image_window.mainloop()









# Create the application
root = tk.Tk()
root.title("TTPClassifierPLUS")

# Configure the root grid to expand and center-align contents
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

# Set the initial size of the window, which will be resizable
root.geometry('1200x900')

app = Application(master=root)

# Run the application
app.mainloop()