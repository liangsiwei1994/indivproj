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

# Download latest relationship data
# attackdata = attackToExcel.get_stix_data("enterprise-attack")
# techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack")
# df = stixToDf.relationshipsToDf(attackdata)
# df2 = df["relationships"]
# print(df2)

# Don't download if there is no wifi access
df2 = pd.read_csv("relationship1.csv")

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

    text = pattern_open.sub("", text)  # Remove "<code>"
    text = pattern_close.sub("", text)  # Remove "</code> " with optional trailing whitespace

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
df2['mapping description'] = df2['mapping description'].apply(replace_links)
df2['mapping description'] = df2['mapping description'].apply(replace_the)

# Identify the parent ID
df2['parent_ID'] = df2['target ID'].str[:5]

# Create a column for the sub-technique ID (to match the dataframe layout of the reference file used by the original research)
df2['null'] = np.nan

# Extract only relevant columns
df2 = df2[['parent_ID', 'null', 'target name', 'mapping description']]

# Rename the column to match the previous work reference dataset
df2 = df2.rename(columns={"parent_ID": "ID", "null": "subtech_ID", "target name": "Name", "mapping description": "Description"})

# Get the tactics of each techniques and drop the PRE ones
attackdata = attackToExcel.get_stix_data("enterprise-attack")
techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack")
techniques_df = techniques_data["techniques"]
techniques_df = techniques_df[["ID", "tactics"]]

# Get the tactics of each technique
df2 = df2.merge(techniques_df, on="ID", how='left')

# If it is the PRE matrix, remove it (because the procedure of PRE is too generic and confuses the model)
df2 = df2[~df2['tactics'].isin(['Reconnaissance', 'Resource Development'])]

# Get the original reference dataset
df1 = pd.read_csv("enterprise-techniques.csv")
df1 = df1.rename(columns={"Unnamed: 1" : "subtech_ID"})

# Represent the procedures using sub-ID value '0.1' and insert it to 1 column below the original ID in the original data used by the previous project
counts = {}
for index2, row in df2.iterrows():
    if row['ID'] in df1['ID'].values:
        index1 = df1[df1['ID'] == row['ID']].index[0]
        row_df = pd.DataFrame(row).T
        row_df['ID'] = np.nan
        row_df['subtech_ID'] = 0.1
        df1 = pd.concat([df1.loc[:index1], row_df, df1.loc[index1+1:]]).reset_index(drop = True)

# Print info() to check
print(df1.info())

# Save df2 to check, and df1 (appended with procedure) for usage 
df2.to_csv("relationship1_filtered1.csv")
df1.to_csv("enterprise-techniques-appended.csv")