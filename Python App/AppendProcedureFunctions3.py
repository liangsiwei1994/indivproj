#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jun 26 08:46:40 2023

@author: siweiliang
"""
import mitreattack.attackToExcel.attackToExcel as attackToExcel
import mitreattack.attackToExcel.stixToDf as stixToDf
import numpy as np
import pandas as pd
from datetime import date
import regex as re
from sentence_transformers import SentenceTransformer
from MitreDataFunctions import setup_techniques_for_cos_similarity

# THIS FUNCTION WAS ORIGINALLY IN AppendProcedureFunctions3.py!!!!

bert_model = SentenceTransformer('basel/ATTACK-BERT')

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

embedding_memo = {}

def get_embedding(txt):
    if txt in embedding_memo:
        return embedding_memo[txt]
    emb = bert_model.encode([txt])[0]
    embedding_memo[txt] = emb
    return emb

def get_embedding_processed(txt1):
    # print(txt1)
    for pattern_name, pattern_list in patterns.items():
        for pattern in pattern_list:
            txt1 = pattern.sub(replacements[pattern_name], txt1)

    p1 = get_embedding(txt1)
    return p1


def setup_file_for_reference(version = None):
    
    ####################################################################################################
    # Part 1 creates the basic reference file
    ####################################################################################################
    
    # Download latest relationship data
    if version is None:
        attackdata = attackToExcel.get_stix_data("enterprise-attack")
        techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack")
        df = stixToDf.relationshipsToDf(attackdata)
        df2 = df["relationships"]
        print(df2)
    else:
        attackdata = attackToExcel.get_stix_data("enterprise-attack", version)
        techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack")
        df = stixToDf.relationshipsToDf(attackdata)
        df2 = df["relationships"]
        print(df2)
    
    
    # Don't download if there is no wifi access
    # df2 = pd.read_csv("relationship1.csv")
    
    # Print column info to check
    # for col in df2.columns:
    #     print(col)
    
    # Only extract relationships that describes a "Procedure" for a technique
    df2 = df2[df2["target type"] == "technique"]
    df2 = df2[df2["mapping type"] == "uses"]
    
    # Remove the tags <code> ... </code>
    def remove_tags(text):
        pattern_open = re.compile(r"<code>")
        pattern_close = re.compile(r"</code>\s*")
    
        text = pattern_open.sub(" ", text)  # Remove "<code>"
        text = pattern_close.sub(" ", text)  # Remove "</code> " with optional trailing whitespace
    
        return text
    
    # Remove all "(Citations: ... )" in the text
    def remove_citation(text):
        pattern = r"\(Citation: .*?\)"
        cleaned_text = re.sub(pattern, "", text)
        return cleaned_text
    
    # Function to remove newline if it is the first character in the description
    def remove_newline_at_start(text):
        if text.startswith("\n"):
            return text[1:]
        return text
    
    # Remove the hyperlinked text in the description and generalize it
    def replace_links(text):
        pattern = r'\[(.*?)\]\((https://.*?)\)'
        
        # Replace softwares with the word 'The malware' if this is the first word in the sentence (because procedures are mostly written in a single sentence), else just 'the malware'.
        # replacement = lambda match: 'the malware' if 'software' in match.group(2) else match.group(0)
        replacement = lambda match: 'The malware' if 'software' in match.group(2) and not re.search(r'\S', match.string[:match.start()]) else ('the malware' if 'software' in match.group(2) else match.group(0))
        
        # Replace softwares with the word 'The attack' if this is the first word in the sentence (because procedures are mostly written in a single sentence), else just 'the attack'.
        # replacement1 = lambda match: 'the attack' if 'campaigns' in match.group(2) else match.group(0)
        replacement1 = lambda match: 'The attack' if 'campaigns' in match.group(2) and not re.search(r'\S', match.string[:match.start()]) else ('the attack' if 'campaigns' in match.group(2) else match.group(0))
        
        # Replace softwares with the word 'The threat actors' if this is the first word in the sentence (because procedures are mostly written in a single sentence), else just 'the threat actors'.
        # replacement2 = lambda match: 'the threat actors' if 'groups' in match.group(2) else match.group(0)
        # replacement2 = lambda match: 'The threat actors' if 'groups' in match.group(2) and not re.search(r'\S', match.string[:match.start()]) else 'the threat actors'
        replacement2 = lambda match: 'The threat actors' if 'groups' in match.group(2) and not re.search(r'\S', match.string[:match.start()]) else ('the threat actors' if 'groups' in match.group(2) else match.group(0))
    
        # Replace remove the link of techniques and the square brackets around the techniques
        replacement3 = lambda match: match.group(1) if 'techniques' in match.group(2) else match.group(0)
        
        # Clean the text using the logic above
        cleaned_text = re.sub(pattern, replacement, text)
        cleaned_text = re.sub(pattern, replacement1, cleaned_text)
        cleaned_text = re.sub(pattern, replacement2, cleaned_text)
        cleaned_text = re.sub(pattern, replacement3, cleaned_text)
        
        return cleaned_text
    
    # Remove the hyperlinked text in the description and WITHOUT generalizing it
    def replace_links_no_generalize(text):
        pattern = r'\[(.*?)\]\((https://.*?)\)'
        
        # Replace softwares with the word 'The malware' if this is the first word in the sentence (because procedures are mostly written in a single sentence), else just 'the malware'.
        # replacement = lambda match: 'the malware' if 'software' in match.group(2) else match.group(0)
        replacement = lambda match: match.group(1) if 'software' in match.group(2) and not re.search(r'\S', match.string[:match.start()]) else (match.group(1) if 'software' in match.group(2) else match.group(0))
        
        # Replace softwares with the word 'The attack' if this is the first word in the sentence (because procedures are mostly written in a single sentence), else just 'the attack'.
        # replacement1 = lambda match: 'the attack' if 'campaigns' in match.group(2) else match.group(0)
        replacement1 = lambda match: match.group(1) if 'campaigns' in match.group(2) and not re.search(r'\S', match.string[:match.start()]) else (match.group(1) if 'campaigns' in match.group(2) else match.group(0))
        
        # Replace softwares with the word 'The threat actors' if this is the first word in the sentence (because procedures are mostly written in a single sentence), else just 'the threat actors'.
        # replacement2 = lambda match: 'the threat actors' if 'groups' in match.group(2) else match.group(0)
        # replacement2 = lambda match: 'The threat actors' if 'groups' in match.group(2) and not re.search(r'\S', match.string[:match.start()]) else 'the threat actors'
        replacement2 = lambda match: match.group(1) if 'groups' in match.group(2) and not re.search(r'\S', match.string[:match.start()]) else (match.group(1) if 'groups' in match.group(2) else match.group(0))
    
        # Replace remove the link of techniques and the square brackets around the techniques
        replacement3 = lambda match: match.group(1) if 'techniques' in match.group(2) else match.group(0)
        
        # Clean the text using the logic above
        cleaned_text = re.sub(pattern, replacement, text)
        cleaned_text = re.sub(pattern, replacement1, cleaned_text)
        cleaned_text = re.sub(pattern, replacement2, cleaned_text)
        cleaned_text = re.sub(pattern, replacement3, cleaned_text)
        
        return cleaned_text
    
    # Replace all "the the" in the text because of the function "replace_links"
    def replace_the(text):
        
        pattern = r'The the'
        replacement = 'The'
        cleaned_text = re.sub(pattern, replacement, text, count=1)
        
        pattern = r'The The'
        replacement = 'The'
        cleaned_text = re.sub(pattern, replacement, cleaned_text, count=1)
        
        pattern = r'the The'
        replacement = 'the'
        cleaned_text = re.sub(pattern, replacement, cleaned_text, count=1)
        
        pattern = r'the the'
        replacement = 'the'
        cleaned_text = re.sub(pattern, replacement, cleaned_text)
        
        return cleaned_text
    
    # Clean the data
    df2['mapping description'] = df2['mapping description'].apply(remove_tags)
    df2['mapping description'] = df2['mapping description'].apply(remove_citation)
    df2['mapping description'] = df2['mapping description'].apply(remove_newline_at_start)
    
    # Create a new dataframe for training data without changing the name
    df3 = df2.copy()
    df2['mapping description'] = df2['mapping description'].apply(replace_links)
    df3['mapping description'] = df3['mapping description'].apply(replace_links_no_generalize)
    df2['mapping description'] = df2['mapping description'].apply(replace_the)
    
    df3.to_csv("train_data.csv")
    
    # Identify the parent ID
    df4 = df2.copy()
    df4['parent_ID'] = df2['target ID']
    df2['parent_ID'] = df2['target ID'].str[:5]
    
    # Create a column for the sub-technique ID (to match the dataframe layout of the reference file used by the original research)
    df4['null'] = np.nan
    df2['null'] = np.nan
    
    # Extract only relevant columns
    df4 = df4[['parent_ID', 'null', 'target name', 'mapping description']]
    df2 = df2[['parent_ID', 'null', 'target name', 'mapping description']]
    
    # Rename the column to match the previous work reference dataset
    df4 = df4.rename(columns={"parent_ID": "ID", "null": "subtech_ID", "target name": "Name", "mapping description": "Description"})
    df2 = df2.rename(columns={"parent_ID": "ID", "null": "subtech_ID", "target name": "Name", "mapping description": "Description"})
    
    # Get the tactics of each techniques and drop the PRE ones
    attackdata = attackToExcel.get_stix_data("enterprise-attack")
    techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack")
    techniques_df = techniques_data["techniques"]
    techniques_df = techniques_df[["ID", "tactics"]]
    
    # Get the tactics of each technique
    df4 = df4.merge(techniques_df, on="ID", how='left')
    df2 = df2.merge(techniques_df, on="ID", how='left')
    
    # If it is the PRE matrix, remove it (because the procedure of PRE is too generic and confuses the model)
    # df4 = df4[~df4['tactics'].isin(['Reconnaissance', 'Resource Development'])]
    # df2 = df2[~df2['tactics'].isin(['Reconnaissance', 'Resource Development'])]
    
    # Get the original reference dataset
    # df1 = pd.read_csv("enterprise-techniqueslatest24July2023.csv")
    
    setup_techniques_for_cos_similarity(version)
    
    if version is None:
        df1 = pd.read_csv("enterprise-techniqueslatest24August2023.csv")
        df1.insert(0, '', '')
    else:
        df1 = pd.read_csv("enterprise-techniques" + version[:3] + ".csv")
        df1.insert(0, '', '')
    # # If original df
    df1 = df1.rename(columns={"Unnamed: 1" : "subtech_ID"})
    # If use v12
    # df1 = df1.rename(columns={"ID" : "subtech_ID"})
    # df1 = df1.rename(columns={"parent_ID" : "ID"})
    df5 = df1
    df5['Procedure'] = np.nan
    
    # Represent the procedures using sub-ID value '0.1' and insert it to 1 column below the original ID in the original data used by the previous project
    # counts = {}
    # for index2, row in df2.iterrows():
    #     if row['ID'] in df1['ID'].values:
    #         index1 = df1[df1['ID'] == row['ID']].index[0]
    #         row_df = pd.DataFrame(row).T
    #         row_df['ID'] = np.nan
    #         row_df['subtech_ID'] = 0.1
    #         df1 = pd.concat([df1.loc[:index1], row_df, df1.loc[index1+1:]]).reset_index(drop = True)
            
    
    # for index2, row in df5.iterrows():
    #     if pd.isnull(row['ID']):
    #         df5.iloc[index2, 0] = df5.iloc[index2-1, 0]
            
    for index2, row in df5.iterrows():
        if pd.isnull(row['ID']):
            df5.iloc[index2, 1] = df5.iloc[index2-1, 1]
    
    df5 = df5.rename(columns={"description": "Description"})
    
    
    
    print(df5.info(()))
        
    # df5 = description
    # df4 = procedure sentences
    
    count = 0
    counts = {}
    for index2, row in df4.iterrows():
        if row['ID'][:5] in df5['ID'].values:
            
            # Populate single row df to be added
            row_df = pd.DataFrame(row).T
            # print(len(row_df.iloc[0, 0]))
            row_df['subtech_ID'] = 0.1
            
            # Match technique's description with technique AND subtechnique's procedure sentences
            # head(1) takes the first row
            index1 = df5[df5['ID'] == row['ID'][:5]].head(1).index[0]
            if pd.isnull(df5.loc[index1]['Procedure']):
                df5.iloc[index1, 5] = row_df.iloc[0, 3]
            else:
                df5 = pd.concat([df5.loc[:index1], row_df, df5.loc[index1+1:]]).reset_index(drop = True)
                # df5.iloc[index1+1, 0] = df5.iloc[index1, 0]
                df5.iloc[index1+1, 1] = df5.iloc[index1, 1]
                df5.iloc[index1+1, 2] = df5.iloc[index1, 2]
                df5.iloc[index1+1, 3] = df5.iloc[index1, 3]
                df5.iloc[index1+1, 4] = df5.iloc[index1, 4]
                df5.iloc[index1+1, 5] = row_df.iloc[0, 3]
            
            # Match subtechnique's description with subtechnique's procedure sentences
            # If this procedure sentence belongs to subtechnique, find the matching subtechnique
            if (len(row_df.iloc[0,0]) > 5):
                # print("HEREEE")
                # print(row['ID'][5:9])
                # print(row['ID'][:5])
                # print(df5['subtech_ID'].astype(str).str[1:5])
                # print(df5[(df5['ID'] == row['ID'][:5]) & (df5['subtech_ID'].astype(str).str[1:5] == row['ID'][5:9])])
                if (row['ID'][5:9] == '.010'):
                    index3 = df5[(df5['ID'] == row['ID'][:5]) & (df5['subtech_ID'].astype(str).str[1:4] == row['ID'][5:8])].index[0]
                else:
                    index3 = df5[(df5['ID'] == row['ID'][:5]) & (df5['subtech_ID'].astype(str).str[1:5] == row['ID'][5:9])].index[0]
                # If it's the first time reaching the subtechnique
                if pd.isnull(df5.loc[index3]['Procedure']):
                    df5.iloc[index3, 5] = row_df.iloc[0, 3]
                else:
                    df5 = pd.concat([df5.loc[:index3], row_df, df5.loc[index3+1:]]).reset_index(drop = True)
                    # df5.iloc[index3+1, 0] = df5.iloc[index3, 0]
                    df5.iloc[index3+1, 1] = df5.iloc[index3, 1]
                    df5.iloc[index3+1, 2] = df5.iloc[index3, 2]
                    df5.iloc[index3+1, 3] = df5.iloc[index3, 3]
                    df5.iloc[index3+1, 4] = df5.iloc[index3, 4]
                    df5.iloc[index3+1, 5] = row_df.iloc[0, 3]
                    df5.loc[index3+1, 'subtech_ID'] = np.nan
                    
            # Match subtechnique's description with technique's procedure sentences
            # If this procedure sentence belongs to technique, find the matching SUBTECHNIQUE
            else:
                # print(row_df['ID'])
                match_condition1 = df5['ID'] == row['ID']
                match_condition2 = pd.notnull(df5['subtech_ID'])
                
                combined_match_condition = match_condition1 & match_condition2
                
                filtered_df5 = df5[combined_match_condition]
                
                indexes = filtered_df5.index.tolist()
                # print(indexes)
                
                index_increment = 0
                for relevant_index_original in indexes:
                    relevant_index = relevant_index_original + index_increment
                    df5 = pd.concat([df5.loc[:relevant_index], row_df, df5.loc[relevant_index+1:]]).reset_index(drop = True)
                    df5.iloc[relevant_index+1, 1] = df5.iloc[relevant_index, 1]
                    df5.iloc[relevant_index+1, 2] = df5.iloc[relevant_index, 2]
                    df5.iloc[relevant_index+1, 3] = df5.iloc[relevant_index, 3]
                    df5.iloc[relevant_index+1, 4] = df5.iloc[relevant_index, 4]
                    df5.iloc[relevant_index+1, 5] = row_df.iloc[0, 3]
                    df5.loc[relevant_index+1, 'subtech_ID'] = np.nan
                    index_increment = index_increment + 1

    df5 = df5[['ID', 'subtech_ID', 'Name', 'Description', 'Procedure']]
        
    df5.to_csv(version + ".csv")

    ####################################################################################################
    # Part 2 creates the embedded reference file in .pkl
    ####################################################################################################
    

    df5['Name_embedding'] = df5['Name'].apply(get_embedding_processed)
    df5['Description_embedding'] = df5['Description'].apply(get_embedding_processed)
    df5['Procedure_embedding'] = df5['Procedure'].apply(lambda x: get_embedding_processed(x) if pd.notnull(x) else np.nan)
    df5.to_pickle(version+".pkl")
    print("done!!")
    
    
    
    
    
    
    
    
    
    
    