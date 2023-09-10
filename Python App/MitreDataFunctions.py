#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jun 13 12:56:04 2023

@author: siweiliang
"""

import mitreattack.attackToExcel.attackToExcel as attackToExcel
import mitreattack.attackToExcel.stixToDf as stixToDf
import numpy as np
import pandas as pd
from datetime import date
import regex as re

# def main():
    
#     # # To get the unique pair of technique and tacticS combination
#     # df = get_technique_df()
#     # tactic_technique_combi = get_unique_tactic_technique_pair(df)
    
#     # # To get the formate of the enterprise matrix for cosine similarity comparison
#     # setup_techniques_for_cos_similarity("v11.0")
    
#     # Function to test get name using ID function
#     name = get_technique_name('T1090')
#     print(name)
    


    
# Function to get the respective version / latest version of technique details
def get_technique_df(version = None):
    
    # Download and parse latest version of ATT&CK STIX data
    if version is None:
        attackdata = attackToExcel.get_stix_data("enterprise-attack")
    else:
        attackdata = attackToExcel.get_stix_data("enterprise-attack", version)
    techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack")
    
    # # Get techniques info (returned to be used to get technique's name)
    techniques_df = techniques_data["techniques"]
    
    techniques_df_copy = techniques_df.copy()
    
    # This is to get technique's name for the graph
    techniques_df_copy2 = techniques_df_copy[techniques_df_copy["is sub-technique"] == False]
    techniques_df_copy3 = techniques_df_copy2[['ID', 'name']]
    
    technique_name_df_for_graph = techniques_df_copy3.copy()
    
    
    # save to csv to check
    # df1.to_csv("unique tactic technique.csv")
    
    # techniques_df.to_csv("techniques_dfv12.csv")
    
    # techniques_df = pd.read_csv("techniques_dfv11.csv")
    
    # check the columns in techniques's info
    # for col in techniques_df.columns:
    #     print(col)
        
    # print(techniques_df["version"].unique())
    # print(techniques_df.info())
    
    
    
    
    
    
    
    # From here onwards is to create df to get unique tactic technique pair
    # Set up a column to store parent technique name
    techniques_df["parent_name"] = np.nan
    
    # Iterate through each row and fill up the parent technique's name or it's own name if it's not a subtechnique
    for index, row in techniques_df.iterrows():
        techniques_df.at[index, "parent_name"] = techniques_df[techniques_df["ID"] == row["ID"][:5]]["name"].iloc[0]
        
    # Save to csv file to check
    techniques_df.to_csv("Check Parent Name.csv")
    
    
    
    # Replace the ID label the parent's ID
    for index, row in techniques_df.iterrows():
        techniques_df.at[index, "parent_ID"] = techniques_df[techniques_df["ID"] == row["ID"][:5]]["ID"][:5].iloc[0]
    
    # Save to csv file to check ID
    techniques_df.to_csv("Check Parent ID.csv")
    
    df1 = techniques_df.drop_duplicates(subset=["parent_ID", "parent_name", "tactics"]) 
    
    # keep only technique and tactic columns
    df1 = df1[["parent_ID", "parent_name", "tactics"]]
    
    # split tactics into individual array of elements
    df1["tactics"] = df1["tactics"].str.split(", ")
    
    tactic_technique_combi_for_graph = df1.copy()
    
    return tactic_technique_combi_for_graph, technique_name_df_for_graph



# Function to get the unique technique and tacticS pair from the techniques details extracted earlier
# def get_unique_tactic_technique_pair(df):
    
#     # Get unique pairs of tactic-technique combination
#     df1 = df.drop_duplicates(subset=["parent_ID", "parent_name", "tactics"]) 
    
#     # keep only technique and tactic columns
#     df1 = df1[["parent_ID", "parent_name", "tactics"]]
    
#     # split tactics into individual array of elements
#     df1["tactics"] = df1["tactics"].str.split(", ")
    
#     # save to csv to check
#     # df1.to_csv("unique tactic technique.csv")
    
#     return df1



# # Function to remove newline if it is the first character in the description
# def remove_newline_at_start(text):
#     if text.startswith("\n"):
#         return text[1:]
#     return text

# # Remove the tags <code> ... </code>
# def remove_tags(text):
#     pattern_open = re.compile(r"<code>")
#     pattern_close = re.compile(r"</code>\s*")

#     text = pattern_open.sub("", text)  # Remove "<code>"
#     text = pattern_close.sub("", text)  # Remove "</code> " with optional trailing whitespace

#     return text

# # Remove the hyperlinked text in the description
# def replace_technique_links(text):
#     pattern = r'\[(.*?)\]\((https://.*?)\)'
#     replacement = lambda match: match.group(1)
#     cleaned_text = re.sub(pattern, replacement, text)
    
#     return cleaned_text

# # Remove all "(Citations: ... )" in the text
# def remove_citation(text):
#     pattern = r"\(Citation: .*?\)"
#     cleaned_text = re.sub(pattern, "", text)
#     return cleaned_text

# # (Trial) To split the text into individual sentences
# def split_text(text):
#     pattern = r'(?<!\b(?:i\.e|e\.g|Mr|Ms)\.)\.(?!\w)'
#     split_text = re.split(pattern, text)
#     return split_text



# # Set up the csv file for cosine similarity
# def setup_techniques_for_cos_similarity(version = None):
    
#     # # download and parse latest version of ATT&CK STIX data
#     if version is None:
#         attackdata = attackToExcel.get_stix_data("enterprise-attack")
#     else:
#         attackdata = attackToExcel.get_stix_data("enterprise-attack", version)
#     techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack")
    
#     # Get techniques info
#     techniques_df = techniques_data["techniques"]
#     # techniques_df.to_csv("techniques_df"+version[:3]+".csv")
    
#     # Replace the ID label the parent's ID
#     for index, row in techniques_df.iterrows():
#         techniques_df.at[index, "parent_ID"] = techniques_df[techniques_df["ID"] == row["ID"][:5]]["ID"][:5].iloc[0]
        
#     # Get the subID ID only
#     techniques_df['ID'] = np.where(techniques_df["is sub-technique"], '0'+techniques_df['ID'].str[5:9], np.nan)
    
#     # Get the parent ID
#     techniques_df['parent_ID'] = np.where(techniques_df["is sub-technique"] == False, techniques_df['parent_ID'], np.nan)
    
#     # Get out only the relevant columns
#     techniques_df = techniques_df[['parent_ID', 'ID', 'name', 'description']]
    
#     # Create a copy to suppress warning
#     techniques_df_copy = techniques_df.copy()
    
#     # Clean up 1: Remove newline at the start so that can split into paragraphs
#     techniques_df_copy['description'] = techniques_df_copy['description'].apply(remove_newline_at_start)
    
#     # Split into paragraphs and retain only the first
#     techniques_df_copy['description'] = techniques_df_copy['description'].str.split('\n').str[0]
    
#     # Clean up further the first paragraph
#     techniques_df_copy['description'] = techniques_df_copy['description'].apply(remove_tags)
#     techniques_df_copy['description'] = techniques_df_copy['description'].apply(replace_technique_links)
#     techniques_df_copy['description'] = techniques_df_copy['description'].apply(remove_citation)
    
#     # split into individual sentences
#     # techniques_df_copy['description'] = techniques_df_copy['description'].apply(split_text)
    
#     # Save the file
#     if version is None:
#         today = date.today()
#         dateToday = today.strftime("%d%B%Y")
#         techniques_df_copy.to_csv("enterprise-techniqueslatest"+dateToday+".csv")
#     else:
#         techniques_df_copy.to_csv("enterprise-techniques"+version[:3]+".csv")
    


# # Function to get the respective version / latest version of technique details
def get_technique_name(ID, techniques_df_copy3 = None, version = None):
    
    # Download and parse latest version of ATT&CK STIX data
    if version is None and (techniques_df_copy3 is None):
        attackdata = attackToExcel.get_stix_data("enterprise-attack")
        techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack")
        techniques_df = techniques_data["techniques"]
        techniques_df_copy = techniques_df[techniques_df["is sub-technique"] == False]
        techniques_df_copy = techniques_df_copy[['ID', 'name']]
        
    elif techniques_df_copy3 is None:
        attackdata = attackToExcel.get_stix_data("enterprise-attack", version)
        techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack")
        techniques_df = techniques_data["techniques"]
        techniques_df_copy = techniques_df[techniques_df["is sub-technique"] == False]
        techniques_df_copy = techniques_df_copy[['ID', 'name']]
        
    techniques_df_copy = techniques_df_copy3
    
    return techniques_df_copy.loc[techniques_df_copy['ID'] == ID, 'name'].iloc[0]
    





# if __name__ == "__main__":
#     main()
    