#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jun 16 08:40:37 2023

@author: siweiliang
"""

import pygraphviz as pgv
import queue
from MitreDataFunctions import *
import numpy as np
import re
import pandas as pd
import ast


####################################################################################################
# SAMPLE SEQUENCES TO TEST FUNCTIONS LOCALLY
####################################################################################################

# Sequence given in https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-320a
sample = ['T1190', 'T1059', 'T1562', 'T1105', 'T1070', 'T1136', 'T1016', 'T1053', 'T1021', 'T1078', 'T1136', 'T1090', 'T1018', 'T1098', 'T1003']
# Sequence given in https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-321a
# sample = ['T1133', 'T1566', 'T1190', 'T1562', 'T1059', 'T1490', 'T1070', 'T1112', 'T1537', 'T1486']
# Sequence given in https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-074a
# sample = ['T1190', 'T1105', 'T1055', 'T1070', 'T1070', 'T1016', 'T1095', 'T1083', 'T1036', 'T1140', 'T1505']
# To check if initial access can back fill
# sample = ['T1059', 'T1190', 'T1574', 'T1070', 'T1190']
# To check if can move complete mission to the back (look at T1531 being moved to the back)
# sample = ['T1059', 'T1190', 'T1574', 'T1070', 'T1531' ,'T1190'] 
# To check if for complete mission at the back, it will not move back (look at T1494 not being moved to the back after T1531 is not moved to the back)
# sample = ['T1059', 'T1190', 'T1574', 'T1070', 'T1495', 'T1531' ,'T1190']
# Try if got loop but no middle will fail
# sample = ['T1190', 'T1531', 'T1190', 'T1531']
# To check if for complete mission at the back, it will not move back (look at T1494 not being moved to the back)
# sample = ['T1059', 'T1190', 'T1574', 'T1070', 'T1495','T1190', 'T1531']
# To check if can branch out after complete mission 
# sample = ['T1059', 'T1190', 'T1574', 'T1070', 'T1495', 'T1070', 'T1190', 'T1531']
# To check for extremely long cases:
# sample = ['T1190', 'T1105', 'T1055', 'T1070', 'T1070', 'T1016', 'T1095', 'T1083', 'T1036', 'T1140', 'T1531', 'T1105', 'T1055', 'T1070', 'T1070', 'T1016', 'T1095', 'T1083', 'T1036', 'T1140', 'T1531', 'T1105', 'T1055', 'T1070', 'T1070', 'T1016', 'T1095', 'T1083', 'T1036', 'T1140', 'T1531']
# To check if initial access will shift until before recon
# sample = ['T1595', 'T1059', 'T1190', 'T1574', 'T1574','T1070', 'T1190']
# To check if initial access will shift until before recon (no loop)
# sample = ['T1595', 'T1059', 'T1190', 'T1574','T1070', 'T1190']
# To check if initial access will shift if it's initial recon before it
# sample = ['T1595', 'T1190', 'T1059', 'T1574', 'T1070', 'T1190']
# To check if complete mission will be moved to the back
# sample = ['T1595', 'T1190', 'T1059', 'T1574', 'T1070', 'T1531', 'T1190']
# To check if it can create 2 loops
# sample = ['T1190', 'T1105', 'T1055', 'T1070', 'T1070', 'T1016', 'T1095', 'T1083', 'T1036', 'T1140', 'T1505', 'T1105', 'T1055', 'T1070', 'T1070', 'T1016', 'T1095', 'T1083', 'T1036', 'T1140', 'T1505', 'T1105', 'T1055', 'T1070', 'T1070', 'T1016', 'T1095', 'T1083', 'T1036', 'T1140', 'T1505', 'T1123', 'T1124' ,'T1125', 'T1123', 'T1124' ,'T1125']
# Random string to stress test
# sample = ['T1218', 'T1546', 'T1133', 'T1553', 'T1059']

# No Initial Access
# sample = ['T1218', 'T1546', 'T1553', 'T1059']

# No Initial Access w/ loop
# sample = ['T1218', 'T1546', 'T1546', 'T1553', 'T1059']

# Sequence given in https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-320a (No Initial Access)
# sample = ['T1059', 'T1562', 'T1105', 'T1070', 'T1136', 'T1016', 'T1053', 'T1021', 'T1136', 'T1090', 'T1018', 'T1098', 'T1003']

# To check if can add node in between initial recon and non-initial compromise stage
# sample = ['T1595', 'T1059',  'T1574','T1070']

# To check if can add node in between initial recon and non-initial compromise stage (with loop)
# sample = ['T1595', 'T1059',  'T1574','T1070', 'T1070']

# To check if loop add missing loop in front can push behind back
# sample = ['T1190', 'T1531', 'T1495', 'T1531', 'T1495']

# To check if add middle stage missing can still loop properly
# sample = ['T1190', 'T1531', 'T1190', 'T1531']


# To check if add stages behind will affect in front
# sample = ['T1189', 'T1200', 'T1189', 'T1200', 'T1190', 'T1531', 'T1190', 'T1531', 'T1059']

# To check if add stages behind will affect in front
# sample = ['T1190', 'T1531', 'T1495', 'T1059' , 'T1531']

# sample = []

# sample = ['T1059', 'T1574', 'T1074', 'T1070', 'T1136', 'T1016', 'T1053', 'T1559', 'T1078', 'T1105', 'T1102', 'T1003', 'T1078', 'T1021', 'T1112', 'T1053', 'T1090', 'T1018', 'T1518']

# See if the alert box for initial compromise can go after internal recon
sample = ['T1595', 'T1059', 'T1190', 'T1059', 'T1531', 'T1059', 'T1531']

# See if can populate both boxes to alert no initial compromise at start and no complete mission at back with in correct color properly
sample = ['T1059', 'T1190', 'T1531', 'T1059', 'T1531', 'T1059']

# sample = ['T1059', 'T1574', 'T1070', 'T1136', 'T1016', 'T1053', 'T1021','T1105', 'T1105', 'T1102', 'T1003', 'T1078', 'T1021','T1546','T1090', 'T1531' ,'T1018','T1518']











####################################################################################################
# SOME CONFIGS TO MATCH
####################################################################################################

# Create a dictionary of which part(s) of the attack lifecycle each tactic belong to
# <<'Initial Access' : ['Initial Compromise']>> means the tactic 'Initial Access' belongs to the attack lifecycle stage called 'Initial Compromise' 
tactic_lifecycle_mapping = {
    'Reconnaissance'        : ['Initial Reconnaissance'],
    'Resource Development'  : ['Initial Reconnaissance'],
    'Initial Access'        : ['Initial Compromise'],
    'Execution'             : ['Initial Compromise','Establish Foothold', 'Escalate Privilege', 'Internal Reconnaissance', 'Move Laterally', 'Maintain Presence', 'Complete Mission'],
    'Persistence'           : ['Establish Foothold'],               #GROUPED ESTABLISH FOOTHOLD AND MAINTAIN PRESENCE INTO ONE
    'Privilege Escalation'  : ['Escalate Privilege'],
    'Defense Evasion'       : ['Initial Compromise','Establish Foothold', 'Escalate Privilege', 'Internal Reconnaissance', 'Move Laterally', 'Maintain Presence', 'Complete Mission'],
    'Credential Access'     : ['Initial Compromise','Establish Foothold', 'Escalate Privilege', 'Internal Reconnaissance', 'Move Laterally', 'Maintain Presence', 'Complete Mission'],
    'Discovery'             : ['Internal Reconnaissance'],
    'Lateral Movement'      : ['Move Laterally'],
    'Collection'            : ['Complete Mission'],
    'Command and Control'   : ['Initial Compromise','Establish Foothold', 'Escalate Privilege', 'Internal Reconnaissance', 'Move Laterally', 'Maintain Presence', 'Complete Mission'],
    'Exfiltration'          : ['Complete Mission'],
    'Impact'                : ['Complete Mission']
    }

# Expected sequence of stages
stages_seq = ['Initial Reconnaissance', 'Initial Compromise', 'Establish Foothold', 'Escalate Privilege', 'Internal Reconnaissance', 'Move Laterally', 'Maintain Presence', 'Complete Mission']

# Stages that cannot be missing
compulsory_stages = ['Initial Compromise', 'Complete Mission']
# Array to check if the required stages' tactics can be found if we want to backfill (listed in sequence of compulsory stages)
compulsory_stages_specific_tactics = {
    'Initial Compromise'    : ['Initial Access'],
    'Complete Mission'      : ['Collection', 'Exfiltration', 'Impact']
    }

# Stages which can be repeated multiple times in the cycle
cyclical_stages = ['Establish Foothold', 'Escalate Privilege', 'Internal Reconnaissance', 'Move Laterally', 'Maintain Presence']

# Tactics that do not belong to a particular stage
flexible_tactics = ['Execution', 'Defense Evasion', 'Credential Access', 'Command and Control']

# Techniques that can come before initial access
pre_initial_access_tech = ['Reconnaissance', 'Resource Development']

# Regex to match TTP pattern
ttp_pattern = re.compile(r'^T\d{4}$')

tactic_seq = ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact']





####################################################################################################
# THIS FUNCTION CHECKS IF THERE IS INITIAL COMPROMISE AND COMPLETE MISSION
####################################################################################################
def check_initial_compromise_complete_mission(tactic_list):
    initial_compromise_found = False
    complete_mission_found = False
    overall_tactics = []
    for tactics in tactic_list:
        for tactic in tactics:
            overall_tactics.append(tactic)
        
    if any(tactic in compulsory_stages_specific_tactics['Initial Compromise'] for tactic in overall_tactics):
        initial_compromise_found = True
    if any(tactic in compulsory_stages_specific_tactics['Complete Mission'] for tactic in overall_tactics):
        complete_mission_found = True
    
    return initial_compromise_found, complete_mission_found








####################################################################################################
# THIS FUNCTION COMBINES THE STAGE NAMES FOR EACH TECHNIQUE BASED ON THE LOGIC MENTIONED BELOW
####################################################################################################
def combine_stage(techniques_list, tactics_list, stages_list):
    # First, iterate through, if the first position contain tactics in Initial Compromise part of compulsory_stage_specific_tactic, replace the earliest possible stages to only "Initial Compromise"
    for i in range(0, len(tactics_list), 1):
        # Move until the first tactic after initial reconnnaissance tactics
        if any(tactic in pre_initial_access_tech for tactic in tactics_list[i]):
            continue
        elif any(tactic in compulsory_stages_specific_tactics['Initial Compromise'] for tactic in tactics_list[0]):
            stages_list[0] = 'Initial Compromise'
            break
    # Next, go to the end, if the last position contain tactics in Complete Mission part of compulsory_stage_specific_tactic, replace the possible stages to only complete mission
    if any(tactic in compulsory_stages_specific_tactics['Complete Mission'] for tactic in tactics_list[-1]):
        stages_list[-1] = 'Complete Mission'
    # Next, iterate through, if in the middle, for that technique, it has more than 1 possible stages, replace it with 'General Technique', if not, just the 1 stage name it belongs to
    for i in range(0, len(stages_list), 1):
        if (i==0 and isinstance(stages_list[i], str)) or (i == len(stages_list)-1 and isinstance(stages_list[i], str)):
            continue
        if len(stages_list[i]) > 1:
            stages_list[i] = 'General \\n Technique'
        else:
            stages_list[i] = stages_list[i][0]
    return stages_list











####################################################################################################
# THIS SECTION GENERATES THE STRINGS TO POPULATE THE GRAPH NODES
####################################################################################################


# Generate label string for each node using the lifecycle stage name and the technique list given (FOR LOOPED, WILL INDICATE EACH BOX INDIVIDUALLY)
# techniques and stages are fed in as strings, tactic is fed in as list, because technique can belong to more than 1 tactic
def generate_string(stage, tactic_list, technique, attack_phrases, technique_name_df):
    # print(technique)
    result = '<f0> ' + stage + ' | {<f1> '
    # Check if the technique is a TTP, else, don't get technique name, will have error cause cannot find in technique name list
    if bool(ttp_pattern.match(technique)):
        tactic_string = tactic_list[0]
        for i in range(1, len(tactic_list), 1):
            tactic_string = tactic_string + ', ' + tactic_list[i]
        result += (technique + ' - ' + get_technique_name(technique, technique_name_df) + ' (' + tactic_string + ') ' +'\\n')
        result += '"' + attack_phrases + '"' + '\\n'
    else:
        # Print the missing tactics in the sequence
        tactic_string = tactic_list[0]
        for i in range(1, len(tactic_list), 1):
            tactic_string = tactic_string + '\\n' + tactic_list[i]
        if stage == 'Missing \\n Tactics':
            result += (technique + tactic_string + '\\n')
        # This will list all the tactics for initial compromise or complete mission to print that either one of these are missing
        elif stage == 'Mandiant Attack \\n Lifecycle Stage':
            result += (technique + tactic_string + '\\n' + attack_phrases)
        else:
            result += (technique + ' (' + tactic_string + ') ' + '\\n')
    result += '}'
    return result








            

####################################################################################################
# THIS SECTION GENERATES THE GRAPH FILE ITSELF FOR NON-LOOPED (SEQUENTIAL) SEQUENCE
####################################################################################################
# Generate a graph using an array of stages (in sequence) and the techniques involved in each stage
def generate_sequential_graph(stages, tactics, techniques, attack_phrases, missing_tactics, technique_name_df):
    # print(stages)
    # print(tactics)
    # print(techniques)
    # print(attack_phrases)
    
    # Check if there's initial compromsie or complete mission first
    initial_compromise_found, complete_mission_found = check_initial_compromise_complete_mission(tactics)
    
    # Specifically for sequential graph, merge stages that are the same to save space
    # stages, tactics, techniques = merge_same_stage(stages, tactics, techniques)
    
    G = pgv.AGraph(strict=False, directed=True)
    
    # Find 3 types of missing info, no middle loop or doesn't end with impact
    # Can straight away check stages here cause already replaced string in combine_stage
    # Info1: If the last stage is not complete mission, add in a box indicating missing complete mission stage
    if (stages[-1] != 'Complete Mission'):
        stage = 'Complete Mission'
        stages.append(stage)
        if complete_mission_found:
            complete_mission_tactic = 'See red boxes above'
            techniques.append("A 'Complete Mission' tactic was found not at the end, but earlier")
            tactics.append([complete_mission_tactic])
            attack_phrases.append('')
        else:
            complete_mission_tactic = 'No techniques belonging to tactics: ' + compulsory_stages_specific_tactics['Complete Mission'][0]
            for i in range(1, len(compulsory_stages_specific_tactics['Complete Mission']), 1):
                complete_mission_tactic = complete_mission_tactic + ', ' + compulsory_stages_specific_tactics['Complete Mission'][i]
            techniques.append('Missing Info')
            tactics.append([complete_mission_tactic])
            attack_phrases.append('')
        
    # Info 2: Find the first stage that is not initial reconnaissance, if that stage is not initial compromise, add in a box indicating that initial compromise is missing
    for i in range(0, len(tactics), 1):
        # Move until the first tactic after initial reconnnaissance tactics
        if stages[i] == 'Initial Reconnaissance':
            continue
        # Can straight away check stages here cause already replaced string in combine_stage
        elif (stages[i] != 'Initial Compromise'):
            stage = 'Initial Compromise'
            stages.insert(i, stage)
            if initial_compromise_found:
                complete_mission_tactic = 'See green boxes below'
                techniques.insert(i, "An 'Initial Compromise' tactic was found not at the start, but later")
                tactics.insert(i, [complete_mission_tactic])
                attack_phrases.insert(i, '')
            else:
                complete_mission_tactic = 'No techniques belonging to tactics: ' + compulsory_stages_specific_tactics['Initial Compromise'][0]
                for i in range(1, len(compulsory_stages_specific_tactics['Initial Compromise']), 1):
                    complete_mission_tactic = complete_mission_tactic + ', ' + compulsory_stages_specific_tactics['Initial Compromise'][i]
                techniques.insert(i, 'Missing Info')
                tactics.insert(i, [complete_mission_tactic])
                attack_phrases.insert(i, '')
            break
        else:
            break
        
    # If it goes immediately from "Initial Access" to "Complete Mission", create a node to indicate that there's missing info
    final_position_checked = 0
    while (final_position_checked != (len(stages)-1)):
        i = 0
        for i in range(len(stages)):
            if (stages[i] == 'Complete Mission' and stages[i-1] == 'Initial Compromise') and all(stage in ['Complete Mission', 'Initial Compromise'] for stage in stages):
                stages.insert(i, 'Missing Info')
                techniques.insert(i, ['Missing cycle between impact \\n and Initial Compromise'])
                tactics.insert(i, ['No tactics'])
                attack_phrases.insert(i, '')
                break
        final_position_checked = i

    
    initial_compromise_tactic_found = False
    complete_mission_tactic_found = False
    # Create nodes
    for i in range(len(stages)):
        for tactic in tactics[i]:
            if tactic in compulsory_stages_specific_tactics['Initial Compromise']:
                initial_compromise_tactic_found = True
            elif tactic in compulsory_stages_specific_tactics['Complete Mission']:
                complete_mission_tactic_found = True
        if complete_mission_tactic_found and bool(ttp_pattern.match(techniques[i])):
            node_label = generate_string(stages[i], tactics[i], techniques[i], attack_phrases[i], technique_name_df)
            G.add_node(str(i), label = node_label, shape = 'record', color = 'red')
        elif initial_compromise_tactic_found and bool(ttp_pattern.match(techniques[i])):
            node_label = generate_string(stages[i], tactics[i], techniques[i], attack_phrases[i], technique_name_df)
            G.add_node(str(i), label = node_label, shape = 'record', color = 'green')
        else:
            node_label = generate_string(stages[i], tactics[i], techniques[i], attack_phrases[i], technique_name_df)
            G.add_node(str(i), label = node_label, shape = 'record')
        initial_compromise_tactic_found = False
        complete_mission_tactic_found = False

        
    # Create edges
    i = 1
    while i < len(stages):
        # NO MORE BRANCHING!!!!!
        # # If the current stage is 'Complete Mission', means a new branch to highlight we moving on from complete mission (extra benefit if no loop, cause if loop, cannot do this already, the complete mission may loop and it's weird)
        # if stages[i] == 'Complete Mission':
        #     # If it is not the last stage but has a next stage that is not complete mission
        #     print("hereeeeeee")
        #     if i < (len(stages)-1) and stages[i+1] != ('Complete Mission'):
        #         # If connect itself to the previous stage
        #         G.add_edge(str(i-1), str(i))
        #         # Connect the next stage to the previous stage too
        #         G.add_edge(str(i-1), str(i+1))
        #         i = i+2
        #         if i >= len(stages):
        #             break
        #     else:
        #         # If it's the last stage, just add normally
        #         G.add_edge(str(i-1), str(i))
        #         i = i+1
        # else:
        #     G.add_edge(str(i-1), str(i))
        #     i = i+1
        G.add_edge(str(i-1), str(i))
        i = i+1
    
    legend_label='{ Legend |{Mandiant Attack \\n Lifecycle Stage| Technique ID - Technique Name (Tactics) \\n "Attack Phrase" \\n (Refer to full sentence in text for complete analysis)}}'
    
    missing_tactics_string = ''
    for i in range(len(missing_tactics)):
        missing_tactics_string += (missing_tactics[i] + '\\n')
    missing_tactics_label = '{Missing Tactics | {' + missing_tactics_string + '}}'
    
    
    # node_label2 = generate_string(stage2, tactics2, technique2, attack_phrase2, technique_name_df)
    stage = 'Missing \\n Tactics'
    techniques = ''
    node_label = generate_string(stage, missing_tactics, techniques, '', technique_name_df)
    G.add_node("Test_string", label = legend_label, shape = 'record')
    G.add_node("Test_string2", label = missing_tactics_label, shape = 'record')
    G.add_edge("Test_string", "Test_string2", color='transparent')
    G.layout(prog="dot")  # use dot
    G.draw("file.png")
            
    
    
    
    





####################################################################################################
# THIS SECTION GENERATES AN EMPTY GRAPH IF THERE IS NO TECHNIQUE FOUND
####################################################################################################
# Generate a graph using an array of stages (in sequence) and the techniques involved in each stage
def generate_empty_graph(missing_tactics, technique_name_df):
    G = pgv.AGraph(strict=False, directed=True)
    stage = 'No \\n Technique \\n Found'
    techniques = ''
    node_label = generate_string(stage, missing_tactics, techniques, '', technique_name_df)
    G.add_node("Test_string", label = node_label, shape = 'record')
    G.layout(prog="dot")  # use dot
    G.draw("file.png")
    
    
                
                
                
            



####################################################################################################
# THIS IS THE MAIN FUNCTION THAT MAPS THE ATTACK LIFE CYCLE STAGES AND GENERATE THE GRAPH
####################################################################################################

def attack_lifecycle_mapping(technique_list_raw, all_substrings, df = None, version=None):
        
    # Prepare unique tactic technique list
    if (version is None) or (version == "Update"):
        tactic_technique_combi, technique_name_df = get_technique_df()   #get the latest version
    else:
        tactic_technique_combi, technique_name_df = get_technique_df(version)   #get the latest version       
    
    # Get a unique list of tactics
    flattened_list = []
    for sublist in tactic_technique_combi['tactics']:
        # print(sublist.istype())
        flattened_list.extend(sublist)
    tactic_series = pd.Series(flattened_list)
    unique_tactics_list = list(tactic_series.unique())
    
    if technique_list_raw is None or len(technique_list_raw)==0:
        unique_tactics_list = sorted(unique_tactics_list, key=lambda x: (x not in tactic_seq, tactic_seq.index(x) if x in tactic_seq else 0))
        generate_empty_graph(unique_tactics_list, technique_name_df)
        return

    # Place all techniques in a FIFO queue to process
    technique_list = queue.Queue()
    for x in technique_list_raw:
        technique_list.put(x)
    
    # Store the stage sequence along the way
    current_stage_sequence = []
    
    # Store the technique sequence along the way
    current_technique_sequence = []
    
    # Prepare a 2D array to store the tactics for each technique in each stage (cause each technique can have more than 1 tactic)
    current_tactic_sequence = []
    
    # Boolean variable that tracks if 'Initial Compromise', which is a compulsory stage, is filled
    initial_compromise_filled = False
    
    
    # Process each element one by one and add it to graph
    while not technique_list.empty():
        
        # Get the technique to analyze
        current_technique = technique_list.get()
        
        # Get the respective tactics of the technique from the queue
        current_tactics = tactic_technique_combi[tactic_technique_combi["parent_ID"] == current_technique].tactics.iloc[0]
        
        # An array to store the technique's possible attack lifecycle stages (cause if more than 1 tactic, can belong to more than 1 attack lifecycle stage)
        possible_stages = []
        
        # An array to keep track of which tactics is responsible for each of the possible stages
        possible_tactics = []
        
        # Collect the attack lifecycle stages and the tactics and compress into a single list
        for tactic in current_tactics:
            current_stages = tactic_lifecycle_mapping[tactic]
            for i in range(len(current_stages)):
                possible_tactics.append(tactic)
                possible_stages.append(current_stages[i])
                
        # Print all the stages and tactics for each technique to make sure they are compressed into a single list
        # print(current_technique)
        # print(possible_stages)
        # print(possible_tactics)
        # print("------------------------------------------------")
        
        # If it only belongs to 1 stage of attack lifecycle...
        # This section need not worry about flexible tactics because they will not have only 1 possible stage
        current_technique_sequence.append(current_technique)
        current_tactic_sequence.append(current_tactics)  
        current_stage_sequence.append(possible_stages)
    
    # If complete mission is not at the last position, push the latest complete mission to the back
    # current_technique_sequence, current_tactic_sequence, current_stage_sequence = push_complete_mission_back(current_technique_sequence, current_tactic_sequence, current_stage_sequence)
     
    # Combine the name of the stages into 1 for each technique, such that each technique now will have 1 stage, look at the function for the logic
    current_stage_sequence = combine_stage(current_technique_sequence, current_tactic_sequence, current_stage_sequence)
    
    # Check if there is repeating sequence to activate loop graph function or general graph function (if loop function, we will keep things modularised without merging same stages)
    # trial_current_technique_sequence, trial_current_stage_sequence, trial_current_tactic_sequence, repeat_indices = remove_repeats(current_technique_sequence, current_stage_sequence, current_tactic_sequence)

    # Get unique list of tactics in the final sequence then find missing tactics
    unique_current_tactic_list = []
    flattened_tactic_list = []
    for tactic_sublist in current_tactic_sequence:
        flattened_tactic_list.extend(tactic_sublist)
    flattened_tactic_list = pd.Series(flattened_tactic_list)
    unique_current_tactic_list = list(flattened_tactic_list.unique())
    missing_tactics = [tactic for tactic in unique_tactics_list if tactic not in unique_current_tactic_list]
    # Sort the missing_tactics list
    missing_tactics = sorted(missing_tactics, key=lambda x: (x not in tactic_seq, tactic_seq.index(x) if x in tactic_seq else 0))


    # If there is a repeating sequence
    # if repeat_indices:
        
    #     # Remove the repeats and the the position of the loops in the finalized array
    #     current_technique_sequence, current_stage_sequence, current_tactic_sequence, repeat_indices = remove_repeats(current_technique_sequence, current_stage_sequence, current_tactic_sequence)
        
    #     # Generate the loop graph
    #     generate_loop_graph(current_technique_sequence, current_stage_sequence, current_tactic_sequence, repeat_indices, missing_tactics, technique_name_df)
        
    # # If no repeating adjacent sequence
    # else:
    #     print("No adjacent repeating subsequence found.")
    #     print("=========================================")
    # print the graph that merges the techniques of the same stages
    generate_sequential_graph(current_stage_sequence, current_tactic_sequence, current_technique_sequence, all_substrings, missing_tactics, technique_name_df)
    
    return         
            
if __name__ == "__main__":
    substring = ['T1059', 'T1190', 'T1531', 'T1059', 'T1531', 'T1059']
    attack_lifecycle_mapping(sample, substring)
        
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
####################################################################################################
# THIS SECTION GENERATES THE STRINGS TO POPULATE THE GRAPH NODES
####################################################################################################


# Generate label string for each node using the lifecycle stage name and the technique list given (FOR LOOPED, WILL INDICATE EACH BOX INDIVIDUALLY)
# techniques and stages are fed in as strings, tactic is fed in as list, because technique can belong to more than 1 tactic
# def generate_string(stage, tactic_list, technique, technique_name_df):
#     # print(technique)
#     result = '<f0> ' + stage + ' | {<f1> '
#     # Check if the technique is a TTP, else, don't get technique name, will have error cause cannot find in technique name list
#     if bool(ttp_pattern.match(technique)):
#         tactic_string = tactic_list[0]
#         for i in range(1, len(tactic_list), 1):
#             tactic_string = tactic_string + ', ' + tactic_list[i]
#         result += (technique + ' - ' + get_technique_name(technique, technique_name_df) + ' (' + tactic_string + ') ' +'\\n')
#     else:
#         # Print the missing tactics in the sequence
#         tactic_string = tactic_list[0]
#         for i in range(1, len(tactic_list), 1):
#             tactic_string = tactic_string + '\\n' + tactic_list[i]
#         if stage == 'Missing \\n Tactics':
#             result += (technique + tactic_string + '\\n')
#         # This will list all the tactics for initial compromise or complete mission to print that either one of these are missing
#         else:
#             result += (technique + ' (' + tactic_string + ') ' + '\\n')
#     result += 'Trial String. This is a very long text omg omg omg omg omg omg omg omg omg omg omg omg omg omg' + '\\n'
#     result += '}'
#     return result






# Generate label string for each node using the lifecycle stage name and the technique list given (FOR SEQUENTIAL, WILL MERGE BOXES FROM THE SAME STAGE)
# Stage is fed in as string, tactic and technique is fed in as list of strings, we've merged them to display adjacent techniques of same stage in same box
# def generate_merged_string(stage, tactic_list, technique_list, technique_name_df):
#     print(stage)
#     print(tactic_list)
#     print(technique_list)
#     result = '<f0> ' + stage + ' | {<f1> '
#     # Check if the technique is a list, if not list, means it's label for "Missing Tactics" or no Techniques found
#     if isinstance(technique_list, list) and bool(ttp_pattern.match(technique_list[0])):
#         for i in range(len(technique_list)):
#             tactic_string = tactic_list[i][0]
#             for j in range(1, len(tactic_list[i]), 1):
#                 tactic_string = tactic_string + ', ' + tactic_list[i][j]
#                 print(technique_list[i])
#             result += (technique_list[i] + ' - ' + get_technique_name(technique_list[i], technique_name_df) + ' (' + tactic_string + ') ' +'\\n')
#     else:
#         # Print the missing tactics in the sequence
#         tactic_string = tactic_list[0]
#         for i in range(1, len(tactic_list), 1):
#             tactic_string = tactic_string + '\\n' + tactic_list[i]
#         if stage == 'Missing \\n Tactics' or stage == 'No \\n Technique \\n Found':
#             result += (technique_list[0] + tactic_string + '\\n')
#         else:
#             # This will list all the tactics for initial compromise or complete mission to print that either one of these are missing
#             result += (technique_list + ' (' + tactic_string + ') ' + '\\n')
#     result += '}'
#     return result










# ####################################################################################################
# # THIS SECTION GENERATES THE GRAPH FILE ITSELF FOR LOOPED SEQUENCE
# ####################################################################################################
                
# # Generate a graph using an array of stages (in sequence) and the techniques involved in each stage
# def generate_loop_graph(techniques, stages, tactics, repeating_indices, missing_tactics, technique_name_df):
#     print(repeating_indices)
    
#     G = pgv.AGraph(strict=False, directed=True)
    
#     # Check if there's initial compromsie or complete mission first
#     initial_compromise_found, complete_mission_found = check_initial_compromise_complete_mission(tactics)
    
#     # Find 3 types of missing info, no middle loop or doesn't end with impact
#     # Can straight away check stages (no need to index) here cause stages has always been stored as strings
    
#     # Info 1: If the last stage is not "Complete Mission", add in one node indicating that there is no 'Complete Mission' and list all the possible tactics missing
#     if (stages[-1] != 'Complete Mission'):
#         stage = 'Complete Mission'
#         stages.append(stage)
#         if complete_mission_found:
#             complete_mission_tactic = 'See red boxes above'
#             techniques.append("A 'Complete Mission' tactic was found not at the end, but earlier")
#             tactics.append([complete_mission_tactic])
#         else:
#             complete_mission_tactic = 'No techniques belonging to tactics: ' + compulsory_stages_specific_tactics['Complete Mission'][0]
#             for i in range(1, len(compulsory_stages_specific_tactics['Complete Mission']), 1):
#                 complete_mission_tactic = complete_mission_tactic + ', ' + compulsory_stages_specific_tactics['Complete Mission'][i]
#             techniques.append('Missing Info')
#             tactics.append([complete_mission_tactic])
        
#     # Info 2: Look for the first stage after the stages in 'Initial Recon'
#     for i in range(0, len(tactics), 1):
#         # Move until the first tactic after initial reconnnaissance tactics
#         if any(tactic in pre_initial_access_tech for tactic in tactics[i]):
#             continue
#         # Can straight away check stages here cause already replaced string in combine_stage
#         # If the first stage right after the initial recon stages is not initial access, add in a step to indicate missing initial access
#         if (stages[i] != 'Initial Compromise'):
#             stage = 'Initial Compromise'
#             stages.insert(i, stage)
#             if initial_compromise_found:
#                 complete_mission_tactic = 'See green boxes below'
#                 techniques.insert(i, "An 'Initial Compromise' tactic was found not at the start, but later")
#                 tactics.insert(i, [complete_mission_tactic])
#                 # add one to every indices that represent a loop that comes after this one new added node!!!!
#                 repeating_indices = [(start+1, end+1) for start, end in repeating_indices]
#             else:
#                 complete_mission_tactic = 'No techniques belonging to tactics: ' + compulsory_stages_specific_tactics['Initial Compromise'][0]
#                 for i in range(1, len(compulsory_stages_specific_tactics['Initial Compromise']), 1):
#                     complete_mission_tactic = complete_mission_tactic + ', ' + compulsory_stages_specific_tactics['Initial Compromise'][i]
#                 techniques.insert(i, 'Missing Info')
#                 tactics.insert(i, [complete_mission_tactic])
#                 # add one to every indices that represent a loop that comes after this one new added node!!!!
#                 repeating_indices = [(start+1, end+1) for start, end in repeating_indices]
#             break
#         # If it is initial compromise, can just break
#         else:
#             break
        
#     # Info 3: If it goes immediately from "Initial Access" to "Complete Mission" AND there are no other stages in the cycle create a node to indicate that there's missing info
#     final_position_checked = 0
#     updated_indices = []
#     # Keep track of the final position checked so that we don't go over the loop
#     while (final_position_checked != (len(stages)-1)):
#         i = 0
#         for i in range(len(stages)):
#             # If the stage is 'Initial Compromise' then immediately 'Complete Mission', but there are no other stages throughout the stages, push this extra node in to indicate potential missing info.
#             if (stages[i] == 'Complete Mission' and stages[i-1] == 'Initial Compromise') and all(stage in ['Complete Mission', 'Initial Compromise'] for stage in stages):
#                 stages.insert(i, 'Missing Info')
#                 # ADD STRING BECAUSE TECHNIQUE GOT PATTERN MATCHING USING REGEX!!
#                 techniques.insert(i, 'Missing cycle between impact \\n and initial compromise')
#                 tactics.insert(i, ['No tactics'])
#                 for start, end in repeating_indices:
#                     # If the repeating indices that shows where got loop starts after this initial compromise to complete mission portion, 
#                     # If this loop comes entirely before the start and end, then both start and end add 1:
#                     if i <= start and i < end:
#                         end += 1
#                         start += 1
#                         updated_indices.append((start, end)) 
#                     # Else if fall within the loop, then add in the end only.
#                     elif start <= i-1 <= end and start <= i <= end:
#                         end += 1
#                         updated_indices.append((start, end))
#                     # If not, just add in the original positions
#                     else:
#                         updated_indices.append((start, end))
#                 break
#         final_position_checked = i
#     # If indices have been updated, update the list of repeating indices
#     if updated_indices:
#         repeating_indices = updated_indices
    
#     initial_compromise_tactic_found = False
#     complete_mission_tactic_found = False
#     # Create nodes
#     for i in range(len(stages)):
#         for tactic in tactics[i]:
#             if tactic in compulsory_stages_specific_tactics['Initial Compromise']:
#                 initial_compromise_tactic_found = True
#             elif tactic in compulsory_stages_specific_tactics['Complete Mission']:
#                 complete_mission_tactic_found = True
#         if complete_mission_tactic_found and bool(ttp_pattern.match(techniques[i])):
#             node_label = generate_string(stages[i], tactics[i], techniques[i], technique_name_df)
#             G.add_node(str(i), label = node_label, shape = 'record', color = 'red')
#         elif initial_compromise_tactic_found and bool(ttp_pattern.match(techniques[i])):
#             node_label = generate_string(stages[i], tactics[i], techniques[i], technique_name_df)
#             G.add_node(str(i), label = node_label, shape = 'record', color = 'green')
#         else:
#             node_label = generate_string(stages[i], tactics[i], techniques[i], technique_name_df)
#             G.add_node(str(i), label = node_label, shape = 'record')
#         initial_compromise_tactic_found = False
#         complete_mission_tactic_found = False
        
#     # Create edges
#     i = 1
#     while i < len(stages):
#         G.add_edge(str(i-1), str(i))
#         i = i+1
            
#     # Add the loop at the mentioned repeated starts and ends
#     for repeats in repeating_indices:
#         print(repeats)
#         G.add_edge(repeats[1], repeats[0])
    
#     stage = 'Missing \\n Tactics'
#     techniques = ''
#     node_label = generate_string(stage, missing_tactics, techniques, technique_name_df)
#     G.add_node("Test_string", label = node_label, shape = 'record')
#     G.add_edge("Test_string", "Test_string2", color='transparent')
#     G.add_node("Test_string2", label = node_label, shape = 'record')
#     G.layout(prog="dot")  # use dot
#     G.draw("file.png")
            
    







####################################################################################################
# THIS SECTION GENERATES THE GRAPH FILE ITSELF FOR NON-LOOPED (SEQUENTIAL) SEQUENCE
####################################################################################################
    
# This function specifically merges techniques and tactics of the same stages together (FOR SEQUENTIAL GRAPH ONLY)
# def merge_same_stage(stages, tactics, techniques):
#     # if not stages or not tactics or not techniques or len(stages) != len(tactics) or len(stages) != len(techniques):
#     #     raise ValueError("All lists must be non-empty and have the same length.")       
        
#     # Produce list of strings, each string represents 1 stage
#     merged_stages = []
#     # Produce list of list of list, each list represents a list of tactics for each technique (because 1 technique can have more than 1 tactic)
#     merged_tactics = []
#     # Product list of list, each list represents the technique within that stage
#     merged_techniques = []
    
#     current_stage = stages[0]
#     current_tactic = []
#     current_technique2 = []

#     current_tactic.append(tactics[0])
#     current_technique2.append(techniques[0])
    
#     # Do the stage merging
#     for i in range(1, len(stages)):
#         if stages[i] == current_stage:
#             current_tactic.append(tactics[i])
#             current_technique2.append(techniques[i])
#         else:
#             merged_stages.append(current_stage)
#             merged_tactics.append(current_tactic)
#             merged_techniques.append(current_technique2)
            
#             current_stage = stages[i]
            
#             current_tactic = []
#             current_technique2 = []
#             current_tactic.append(tactics[i])
#             current_technique2.append(techniques[i])
            
            
#     merged_stages.append(current_stage)
#     merged_tactics.append(current_tactic)
#     merged_techniques.append(current_technique2)
    
    
#     return merged_stages, merged_tactics, merged_techniques









####################################################################################################
# THE NEXT 3 FUNCTIONS ARE THERE TO LOOK FOR REPEATING GROUPS WITH THE FOLLOWING LOGIC:
    # 1. FIND THE LARGEST ADJACENT SUBSEQUENCE OF TECHNIQUE SEQUENCE
    # 2. STORE THE INCIDES OF THE START, END OF THE WHOLE REPEATING SUBSEQUENCE, AND THE END OF THE FIRST UNIQUE SUBSEQUENCE IN THE REPEATING SUBSEQUENCE
    # 3. FIND BREAK THE SEQUENCE INTO PARTS IN FRONT AND BEHIND THE SUBSEQUENCE
    # 4. REPEAT ON THE FRONT AND BACK PART TO FIND THE NEXT BIGGEST SUBSEQUENCE AND BREAK IT FURTHER
    # 5. DO IT RECURSIVELY UNTIL LEFT WITH 1 ELEM
# NOTE: THIS INHERENTLY PRIORITIZES THE FIRST SUBSEQUENCE IF THERE IS 2 SUBSEQUENCE OF THE SAME LENGTH THAT IS OVERLAPPING.
####################################################################################################
# Find the start and end indices of the entire repeating subsequence
# def find_adjacent_repeating_group(seq):
#     n = len(seq)
#     for length in range(n // 2, 0, -1):
#         i = 0
#         while i < n - length:
#             subseq = seq[i:i+length]
#             next_start = i
#             count = 0
#             while seq[next_start:next_start+length] == subseq:
#                 count += 1
#                 next_start += length

#             if count >= 2:  # More than one adjacent instance found
#                 return i, next_start-1, i+length  # Return the start, end of the group, and start of first repeat
#             else:
#                 i += 1
                
#     return None, None, None  # No group found

# # Recursively perform the function above
# def recursive_find(seq, offset=0):
#     results = []
    
#     start, end, repeat_start = find_adjacent_repeating_group(seq)
#     while start is not None:
#         # Recur for the segment before the group
#         results.extend(recursive_find(seq[:start], offset))
        
#         # Append the found group with original index
#         results.append((start + offset, end + offset, repeat_start + offset))
        
#         # Update the sequence to look after the found group and repeat
#         seq = seq[end+1:]
#         offset += end + 1
#         start, end, repeat_start = find_adjacent_repeating_group(seq)

#     return results

# # Remove the subsequence based on 3 indices obtained in the earlier function recursive_find
# def remove_repeats(seq, corresponding_array1, corresponding_array2):
#     assert len(seq) == len(corresponding_array1) == len(corresponding_array2), "All arrays should be of the same length"

#     instances = recursive_find(seq)
#     instances.sort(key=lambda x: x[0])
    
#     new_seq = []
#     new_corresponding_array1 = []
#     new_corresponding_array2 = []
#     indices = []
    
#     last_end = -1
    
#     for start, end, repeat_start in instances:
#         new_seq.extend(seq[last_end+1:start])  # Add elements before the current group
#         new_corresponding_array1.extend(corresponding_array1[last_end+1:start])
#         new_corresponding_array2.extend(corresponding_array2[last_end+1:start])
        
#         new_seq.extend(seq[start:repeat_start])  # Add only the first occurrence
#         new_corresponding_array1.extend(corresponding_array1[start:repeat_start])
#         new_corresponding_array2.extend(corresponding_array2[start:repeat_start])
        
#         indices.append((len(new_seq) - (repeat_start - start), len(new_seq) - 1))  # Append the start and end of the first occurrence based on new_seq position
#         last_end = end
        
#     new_seq.extend(seq[last_end+1:])  # Add remaining elements after the last group
#     new_corresponding_array1.extend(corresponding_array1[last_end+1:])
#     new_corresponding_array2.extend(corresponding_array2[last_end+1:])

#     return new_seq, new_corresponding_array1, new_corresponding_array2, indices










####################################################################################################
# THIS FUNCTION CHECKS IF THE END IS COMPLETE MISSION AND IF THERE IS COMPLETE MISSION ALONG THE WAY
####################################################################################################
# def push_complete_mission_back(techniques_list, tactics_list, stages_list):
#     print('WITHIN FUNC')
#     print("PASSED FUNCTION LIST")
#     print(tactics_list)
#     print("Complete Mission Tactics!!")
#     print(compulsory_stages_specific_tactics['Complete Mission'])
#     # look at the last position, if the last tactic is not a complete mission stage
#     if any(tactic not in compulsory_stages_specific_tactics['Complete Mission'] for tactic in tactics_list[-1]):
#         #traverse from the end to the front
#         for i in range(len(tactics_list) - 1, -1, -1):
#             # if there is any tactics that fulfills complete mission, move it to the back
#             if any(tactic in compulsory_stages_specific_tactics['Complete Mission'] for tactic in tactics_list[i]):
#                 # Move that technique to the back
#                 techniques_to_move = techniques_list.pop(i)
#                 techniques_list.append(techniques_to_move)
#                 # Move it's tactic to the back
#                 tactics_to_move = tactics_list.pop(i)
#                 tactics_list.append(tactics_to_move)
#                 # Move it's stages to the back
#                 stages_to_move = stages_list.pop(i)
#                 stages_list.append(stages_to_move)
#                 break
#     return techniques_list, tactics_list, stages_list
                