#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jun 13 12:56:04 2023

@author: siweiliang
"""

import mitreattack.attackToExcel.attackToExcel as attackToExcel
import mitreattack.attackToExcel.stixToDf as stixToDf
import pandas as pd
import numpy as np

def main():
    
    df = get_technique_df()
    
    tactic_technique_combi = get_unique_tactic_technique_pair(df)
    
    



    
def get_technique_df():
    
    # # download and parse latest version of ATT&CK STIX data
    # attackdata = attackToExcel.get_stix_data("enterprise-attack")
    # techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack")
    
    # # Get techniques info
    # techniques_df = techniques_data["techniques"]
    # techniques_df.to_csv("techniques_df.csv")
    
    techniques_df = pd.read_csv("techniques_df.csv")
    
    # check the columns in techniques's info
    # for col in techniques_df.columns:
    #     print(col)
        
    # print(techniques_df["version"].unique())
    
    
    
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
    # techniques_df.to_csv("Check Parent ID.csv")
    
    return techniques_df




def get_unique_tactic_technique_pair(df):
    
    # Get unique pairs of tactic-technique combination
    df1 = df.drop_duplicates(subset=["parent_ID", "parent_name", "tactics"]) 
    
    # keep only technique and tactic columns
    df1 = df1[["parent_ID", "parent_name", "tactics"]]
    
    # split tactics into individual array of elements
    df1["tactics"] = df1["tactics"].str.split(", ")
    
    # save to csv to check
    # df1.to_csv("unique tactic technique.csv")
    
    return df1





if __name__ == "__main__":
    main()
    