#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jun 16 08:40:37 2023

@author: siweiliang
"""

# Assumptions:
# 1) Every 'Initial Compromise' stage must come with an 'Establish Foothold' stage
# 2) Every 'Cyclical Zone' will have an 'Initial Compromise' and 'Establish Foothold' zone
# 3) Every 'Mission Complete' stage must be preceded by at least 1 stage in the 'Cyclical Zone'

import pygraphviz as pgv
import queue
from MitreDataFunctions import *
import numpy as np

# Sequence given in https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-320a
sample = ['T1190', 'T1059', 'T1562', 'T1105', 'T1070', 'T1136', 'T1016', 'T1053', 'T1021', 'T1078', 'T1136', 'T1090', 'T1018', 'T1098', 'T1003']
# Sequence given in https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-321a
# sample = ['T1133', 'T1566', 'T1190', 'T1562', 'T1059', 'T1490', 'T1070', 'T1112', 'T1537', 'T1486']

# Create a dictionary of which part(s) of the attack lifecycle each tactic belong to
# <<'Initial Access' : ['Initial Compromise']>> means the tactic 'Initial Access' belongs to the attack lifecycle stage called 'Initial Compromise' 
tactic_lifecycle_mapping = {
    'Initial Access'        : ['Initial Compromise'],
    'Execution'             : ['Initial Compromise','Establish Foothold', 'Escalate Privilege', 'Internal Reconnaissance', 'Move Laterally', 'Maintain Presence', 'Complete Mission'],
    'Persistence'           : ['Establish Foothold', 'Maintain Presence'],
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
stages_seq = ['Initial Compromise', 'Establish Foothold', 'Escalate Privilege', 'Internal Reconnaissance', 'Move Laterally', 'Maintain Presence', 'Complete Mission']

# Stages that cannot be missing
compulsory_stages = ['Initial Compromise']
# Array to check if the required stages' tactics can be found if we want to backfill (listed in sequence of compulsory stages)
compulsory_stages_specific_tactics = {
    'Initial Compromise'    : ['Initial Access'],
    }

# Stages which can be repeated multiple times in the cycle
cyclical_stages = ['Escalate Privilege', 'Internal Reconnaissance', 'Move Laterally', 'Maintain Presence']

# Tactics that do not belong to a particular stage
flexible_tactics = ['Execution', 'Defense Evasion', 'Credential Access', 'Command and Control']



# Generate label string for each node using the lifecycle stage name and the technique list given
def generate_string(stage, tactic_list, technique_list):
    result = '<f0> ' + stage + ' | {<f1> '
    if (len(technique_list) == 0):
        result += ('Missing compulsory stage')
    else:
        for i in range(len(technique_list)):
            result += (technique_list[i] + ' - ' + get_technique_name(technique_list[i]) + ' (' + tactic_list[i] + ') ' +'\\n')
    result += '}'
    return result


                
# Generate a graph using an array of stages (in sequence) and the techniques involved in each stage
def generate_graph(stages, tactics, techniques):
    
    G = pgv.AGraph(strict=False, directed=True)
    
    # Find 2 types of missing info, no middle loop or doesn't end with impact
    if (stages[-1] != 'Complete Mission'):
        stage = 'Complete Mission'
        stages.append(stage)
        techniques.append([])
        tactics.append([])
        
    # If it goes immediately from "Establish Foothold" to "Complete Mission", create a node to indicate that there's missing info
    final_position_checked = 0
    while (final_position_checked != (len(stages)-1)):
        i = 0
        for i in range(len(stages)):
            if (stages[i] == 'Complete Mission' and stages[i-1] == 'Establish Foothold'):
                stages.insert(i, 'Missing Info')
                techniques.insert(i, ['Missing cycle between impact \\n and establish foothold'])
                tactics.insert(i, ['No tactics'])
                break
        final_position_checked = i
        
        # print("Final Position Checked: " + str(final_position_checked))
        # print("Stages length: " + str(len(stages)))
        

    print(len(stages))
    print(len(tactics))
    print(len(techniques))
    
    # Create nodes
    for i in range(len(stages)):
        # print(i)
        # print("Stages length in create nodes: " + str(len(stages)))
        # print(stages)
        # print("Techniques length in create nodes: " + str(len(techniques)))
        # print(techniques)
        # print(stages)
        # print(techniques[i])
        node_label = generate_string(stages[i], tactics[i], techniques[i])
        G.add_node(str(i), label = node_label, shape = 'record')
        
    # Create edges
    for i in range(1, len(stages)):
        # If the current stage is complete mission/initial access, close the loop in front and add the impact
        if (stages[i] == 'Complete Mission'):
            j = i-2
            # Else close the loop in front
            while (stages[j] not in compulsory_stages):
                j -= 1
            # If it's only 1 node apart, there's no loop to establish between complete missions and est foothold
            if (j != (i-2)):
                G.add_edge(str(i-1), str(j+1), style = 'dashed')
            G.add_edge(str(i-1), str(i))
            
        # If the current stage is 'Initial Compromise', means a new branch began since we start analyzing from second stage
        elif stages[i] == 'Initial Compromise':
            j = i-2
            while (stages[j] not in compulsory_stages):
                j -= 1
            # If previously is 'Complete Mission' stage, connect itself to the last stage in the cylical zone
            if stages[i-1] == 'Complete Mission':
                G.add_edge(str(i-2), str(i))
            # If the previous stage is 'Establish Foothold', then simply connect to it without doing anything else
            elif stages[i-1] == 'Establish Foothold':
                G.add_edge(str(i-1), str(i))
            # Else, close the cyclical loop and start a new branch
            else:
                G.add_edge(str(i-1), str(j))
                G.add_edge(str(i-1), str(i))
        else:
            G.add_edge(str(i-1), str(i))
        
        
    G.layout(prog="dot")  # use dot
    G.draw("file.png")
            
    

# Function to check if all elements in array1 are in array2
def check_elements(array1, array2):
    for element in array1:
        if element not in array2:
            return False
    return True











# Map the list of techniques extracted in sequence of the attack life-cycle
def attack_lifecycle_mapping(technique_list_raw):

    # Place all techniques in a FIFO queue to process
    technique_list = queue.Queue()
    for x in sample:
        technique_list.put(x)
        
    # Prepare unique tactic technique list
    df = get_technique_df("v11.0")
    tactic_technique_combi = get_unique_tactic_technique_pair(df)
    
    # Always start with an 'Initial Compromise' stage
    current_stage_sequence = ['Initial Compromise']
    # Prepare a 2D array to store the techniques in each stage
    current_technique_sequence = [[]]
    # Prepare a 2D array to store the tactics for each technique in each stage
    current_tactic_sequence = [[]]
    # Track initial position of current branch
    current_branch_tracker = 0
    # String that represents the last stage in the stage sequence
    last_stage = current_stage_sequence[-1]
    # Boolean variable that tracks if 'Initial Compromise', which is a compulsory stage, is filled
    # If not filled in the current branch and the program later found an 'Initial Compromise' tactic that doesnt belong to the flexible tactic, 
    # give it the benefit of doubt and use it to fill up the compulsory 'Initial Compromise' stage
    initial_compromise_filled = False
    
    
    # Process each element one by one and add it to graph
    while not technique_list.empty():
        
        # Get the technique to analyze
        current_technique = technique_list.get()
        
        # Get the respective tactics of the techniques from the queue
        current_tactics = tactic_technique_combi[tactic_technique_combi["parent_ID"] == current_technique].tactics.iloc[0]
        
        # An array to store it's attack lifecycle stages
        possible_stages = []
        
        # An array to keep track of which tactics is responsible for each of the possible stages
        possible_tactics = []
        
        # Collect the attack lifecycle stages and the tactics
        for tactic in current_tactics:
            current_stages = tactic_lifecycle_mapping[tactic]
            for i in range(len(current_stages)):
                possible_tactics.append(tactic)
                possible_stages.append(current_stages[i])
                
        # Print all the stages and tactics for each of the stage belong to the current technique to check
        print(current_technique)
        print(possible_stages)
        print(possible_tactics)
        
        # # add a cycle filled later bool!!!!!!!!!!!!!!!!!!
        # if len(current_stage_sequence) > 1:
        #     if (current_stage_sequence[-1] == 'Complete Mission') and initial_compromise_filled and establish_foothold_filled:
        #         # if current sequence belongs to a 'Complete Mission' stage too, add it to complete mission
        #         if 'Complete Mission' in possible_tactics:
        #             current_technique_sequence[-1].append(current_technique)
        #         # Else, start a new branch and add accordingly
        #         else:
        #             current_branch_tracker = len(current_stage_sequence)
        
        
        # If it only belongs to 1 stage of attack lifecycle, just add to that stage in the current branch
        # This section need not worry about flexible tactics because they will not have only 1 possible stage
        if (len(possible_stages) == 1):
            
            # If it is 
            # 1) initial compromise and initial compromise in that branch is not filled
            # 2) Establish Foothold and est. foothold in that branch is not filled (no such tactic as of June 2023)
            # 3) or any other stages
            
            
            # Logic 1: If last stage is impact
            # 1) and current stage is 'Initial Compromise', start a new branch
            # 2) and current stage not one of the flexible tactics, start a new branch too
            # 3) and current stage is one of the flexible tactics, add it to the current branch (this won't happen here so no code is added cause they will have multiple stages)
            if (last_stage == 'Impact'):
                
                if possible_stages[0] == 'Initial Compromise':
                    # Update the branch tracker that a new branch has started
                    current_branch_tracker = len(current_stage_sequence)
                    current_stage_sequence.append('Initial Compromise')
                    current_technique_sequence.append([current_technique])
                    current_tactic_sequence.append([current_tactics[0]])
                    last_stage = 'Initial Compromise'  
                    initial_compromise_filled = True
                    
                else:
                    # Update the branch tracker that a new branch has started
                    current_branch_tracker = len(current_stage_sequence)
                    # Create an empty 'Initial Compromise' stage
                    current_stage_sequence.append('Initial Compromise')
                    current_technique_sequence.append([])
                    current_tactic_sequence.append([])
                    # Create the following stage
                    current_stage_sequence.append(possible_stages[0])
                    current_technique_sequence.append([current_technique])
                    current_tactic_sequence.append([current_tactics[0]])
                    last_stage = possible_stages[0]
                    
                    
            # Logic 2: it is an 'Initial Compromise' only class AND ('Initial Compromised' has not been filled in the current branch OR previous stage is 'Initial Compromise')
            # fill up at the 'Initial Compromise' stage of the current branch. Else, create a new branch (Logic 3).
            elif (possible_stages[0] == 'Initial Compromise') and (not initial_compromise_filled or last_stage == 'Initial Compromise'):
                for i in range(current_branch_tracker, len(current_stage_sequence)):
                    if current_stage_sequence[i] == 'Initial Compromise':
                        current_technique_sequence[i].append(current_technique)
                        # Immediately append tactic because there's only 1 tactic
                        current_tactic_sequence[i].append(current_tactics[0])
                        initial_compromise_filled = True
                        
            
            # Logic 2.1 - 2.2: If it is not an 'Initial Compromise' only class
            elif (possible_stages[0] != 'Initial Compromise'):
                
                # Logic 2.1: If it belongs to one of the cyclical stages, add to the earliest available next cyclical stage
                if last_stage in cyclical_stages:
                    index = cyclical_stages.index(last_stage)
                    for i in range(index, index+len(cyclical_stages)):
                        if (cyclical_stages[i%(len(cyclical_stages))] == possible_stages[0]):
                            if i == index:
                                current_technique_sequence[-1].append(current_technique)
                                current_tactic_sequence[-1].append(current_tactics[0])
                                break
                            else:
                                current_stage_sequence.append(cyclical_stages[i%4])
                                current_tactic_sequence.append([current_tactics[0]])
                                current_technique_sequence.append([current_technique])
                                last_stage = cyclical_stages[i%4]
                                break

                # Logic 2.2: Otherwise, fill up the earliest possible stage
                else:
                    index = stages_seq.index(last_stage)
                    for i in range(index, index+len(stages_seq)):
                        stage = stages_seq[i%len(stages_seq)]
                        if (possible_stages[0] == stage) and stage != 'Initial Compromise':
                            # If the earliest stage is the last existing stage, add to it
                            if i == index:
                                current_technique_sequence[-1].append(current_technique)
                                current_tactic_sequence[-1].append(current_tactics[0])
                            # If not, create a new stage
                            else:
                                current_stage_sequence.append(possible_stages[0])
                                current_technique_sequence.append([current_technique])
                                current_tactic_sequence.append([current_tactics[0]])
                                last_stage = possible_stages[0]
                
                    
            # Logic 3: If it is an 'Initial Compromise' but there is already 'Initial Compromise' in the current branch AND the previous stage is NOT 'Initial Access', start a new branch.
            else:
                current_branch_tracker = len(current_stage_sequence)
                print("+++++++++++++++++++++++++++++++++++++++++++++++++++")
                current_stage_sequence.append('Initial Compromise')
                current_technique_sequence.append([current_technique])
                current_tactic_sequence.append([current_tactics[0]])
                print("---------------------------------------------------")
           
            
        # Logic 4: If the technique belongs to multiple stages of the attack lifecycle, then LOOK AT TACTICS
        # We look at the most specific tactic first, then fill it up based at the latest stage of the closest next stage if the latest stage doesn't match. 
        # Mainly (Defense evasion, Execution, Credential Access and Command and Control)
        else:
            
            # Logic 5: If the previous stage was 'Mission Complete' AND it's a flexible tactic, all the flexible tactic to the 'Mission Complete' Stage
            if (last_stage == 'Mission Complete') :
                
                # Logic 5.1: If the previous stage was 'Mission Complete' AND it's a technique that only belongs to flexible tactics, map the technique to the 'Mission Complete' Stage
                if(check_elements(possible_tactics, flexible_tactics)):
                    current_technique_sequence[-1].append(current_technique)
                    unique_tactic = list(set(possible_tactics))
                    tactic_str = unique_tactic[0]
                    for i in range(1, len(unique_tactic)):
                        tactic_str += (' + ' + unique_tactic[i])
                    current_tactic_sequence[-1].append(tactic_str)
                    
                # Logic 5.2: Else, create a new branch and prioritize all the specific tactics first
                else:
                    possible_tactics_np_array = np.array(possible_tactics)
                    flexible_tactics_np_array = np.array(flexible_tactics)
                    # Note: Exfiltration/Impact won't come here because those will fall above
                    difference = np.setdiff1d(possible_tactics_np_array, flexible_tactics_np_array)
                    mapped = False
                    
                    # Logic 5.2.1: If initial access is found in the current technique's array and initial access is not filled, 
                    # give benefit of doubt and backfill
                    for stage in compulsory_stages:
                        # bool to track if the current technique is mapped, once mapped, stop looping
                       
                        if (check_elements(compulsory_stages_specific_tactics[stage], difference)) :
                            # If initial access is found, check if the current branch is filled, if filled, start a new branch
                            if initial_compromise_filled:
                                current_branch_tracker = len(current_stage_sequence)
                                current_stage_sequence.append(stage)
                                current_tactic_sequence.append([])
                                current_technique_sequence.append([])
                                if stage == 'Initial Compromise':
                                    initial_compromise_filled = False
                            # Loop across the new/existing branch to find initial compromise (which initial access can fill) and fill it up
                            for i in range(current_branch_tracker, len(current_stage_sequence)):
                                if current_stage_sequence[i] == stage:
                                    current_technique_sequence[i].append(current_technique)
                                    tactics_str = compulsory_stages_specific_tactics[stage][0]
                                    # Label the tactic with all the possible tactics
                                    for i in range(1, len(compulsory_stages_specific_tactics[stage])):
                                        tactics_str += (' + ' + compulsory_stages_specific_tactics[i])
                                    current_tactic_sequence[i].append(tactics_str)
                                    initial_compromise_filled = True
                                    last_stage = stage
                                    mapped = True
                                    break
                
                    # Logic 5.2.2: If cannot find compulsory stage in the compulsory stages, move to specific ones but not initial access, then create a new branch
                    if not mapped:
                        # Create an array of all the tactics that doesn't belong the compulsory stage
                        # for stages not in compulsory stage, get their tactics, the find the tactics in the possible tactics
                        compulsory_stages_tactics = sum(compulsory_stages_specific_tactics.values(), [])
                        difference_no_compulsory = np.setdiff1d(difference, compulsory_stages_tactics)
                        possible_specific_stages = []
                        possible_specific_tactics = []
                        
                        
                        # Find all the possible stages based on the tactics that are specific but not compulsory
                        for tactic in difference_no_compulsory:
                            current_stages = tactic_lifecycle_mapping[tactic]
                            for i in range(len(current_stages)):
                                possible_specific_tactics.append(tactic)
                                possible_specific_stages.append(current_stages[i])
                        
                        # Create a new branch and start with 'Initial Compromise' stage but leave it empty
                        current_branch_tracker = len(current_stage_sequence)
                        current_stage_sequence.append('Initial Compromise')
                        current_tactic_sequence.append([])
                        current_technique_sequence.append([])
                                
                        # Find the closest stage to map the current tactic to
                        for stage2 in stages_seq:
                            if stage2 in possible_specific_stages:
                                # Create the string of tactics based on that stage
                                tactic_str = ''
                                for i in range(len(possible_specific_stages)):
                                    if possible_specific_stages[i] == stage2:
                                        tactic_str += possible_specific_tactics[i]
                                current_stage_sequence.append(stage2)
                                current_tactic_sequence.append([tactic_str])
                                current_technique_sequence.append([current_technique])
                                last_stage = stage2
                                mapped = True
                                break
                        
                    # # If the current technique has been mapped, then move to the next technique
                    # if mapped:
                    #     break
            
            #Logic 6: If the previous stage is not 'Mission Complete'
            else:
                
                # Logic 6.1: If the previous stage was 'Mission Complete' AND it's a technique that only belongs to flexible tactics, map the technique to the previous stage
                if(check_elements(possible_tactics, flexible_tactics)):
                    current_technique_sequence[-1].append(current_technique)
                    unique_tactic = list(set(possible_tactics))
                    tactic_str = unique_tactic[0]
                    for i in range(1, len(unique_tactic)):
                        tactic_str += (' + ' + unique_tactic[i])
                    current_tactic_sequence[-1].append(tactic_str)
                    
                # Logic 6.2: Else if 'Initial Compromise' is in one of the stages and it's not filled yet in the current branch, fill it up
                else:
                    possible_tactics_np_array = np.array(possible_tactics)
                    flexible_tactics_np_array = np.array(flexible_tactics)
                    # Note: Exfiltration/Impact won't come here because those will fall above
                    difference = np.setdiff1d(possible_tactics_np_array, flexible_tactics_np_array)
                    mapped = False
                    
                    # Logic 6.2.1: If initial access is found in the current technique's array and initial access is not filled, 
                    # give benefit of doubt and backfill
                    for stage in compulsory_stages:
                        # bool to track if the current technique is mapped, once mapped, stop looping
                        if (check_elements(compulsory_stages_specific_tactics[stage], difference)) :
                            # If initial access is found, check if the current branch is filled, if filled, do not fill and start looking at other specific techniques
                            if not initial_compromise_filled:
                                # Loop across the new/existing branch to find initial compromise (which initial access can fill) and fill it up
                                for i in range(current_branch_tracker, len(current_stage_sequence)):
                                    if current_stage_sequence[i] == stage:
                                        current_technique_sequence[i].append(current_technique)
                                        tactics_str = compulsory_stages_specific_tactics[stage][0]
                                        # Label the tactic with all the possible tactics
                                        for i in range(1, len(compulsory_stages_specific_tactics[stage])):
                                            tactics_str += (' + ' + compulsory_stages_specific_tactics[i])
                                        current_tactic_sequence[i].append(tactics_str)
                                        initial_compromise_filled = True
                                        last_stage = stage
                                        mapped = True
                                        break
                
                    # Logic 6.2.2: If cannot find compulsory stage in the compulsory stages, move to specific ones but not initial access, then create a new branch
                    if not mapped:
                        # Create an array of all the tactics that doesn't belong the compulsory stage
                        # for stages not in compulsory stage, get their tactics, the find the tactics in the possible tactics
                        compulsory_stages_tactics = sum(compulsory_stages_specific_tactics.values(), [])
                        difference_no_compulsory = np.setdiff1d(difference, compulsory_stages_tactics)
                        possible_specific_stages = []
                        possible_specific_tactics = []
                        
                        
                        # Find all the possible stages based on the tactics that are specific but not compulsory
                        for tactic in difference_no_compulsory:
                            current_stages = tactic_lifecycle_mapping[tactic]
                            for i in range(len(current_stages)):
                                possible_specific_tactics.append(tactic)
                                possible_specific_stages.append(current_stages[i])
                                
                        # If last stage not in circular zone, then slowly traverse down the sequence
                        if last_stage not in cyclical_stages:
                            # Find the closest stage to map the current tactic to
                            for stage2 in stages_seq:
                                if stage2 in possible_specific_stages:
                                    # Create the string of tactics based on that stage
                                    tactic_str = ''
                                    for i in range(len(possible_specific_stages)):
                                        if possible_specific_stages[i] == stage2:
                                            tactic_str += possible_specific_tactics[i]
                                    current_stage_sequence.append(stage2)
                                    current_tactic_sequence.append([tactic_str])
                                    current_technique_sequence.append([current_technique])
                                    last_stage = stage2
                                    mapped = True
                                    break
                        
                        # Else, if in cyclical zone, find the closest cylical stage to map the current tactic to
                        else:
                            print("HEREREEEEE")
                            print(last_stage)
                            print(possible_specific_stages)
                            index = cyclical_stages.index(last_stage)
                            for i in range(index, index+len(cyclical_stages)):
                                if cyclical_stages[i%len(cyclical_stages)] in possible_specific_stages:
                                    print("ALERT: " + cyclical_stages[i%len(cyclical_stages)])
                                    # Create the string of tactics based on that stage
                                    tactic_str = ''
                                    for j in range(len(possible_specific_stages)):
                                        if possible_specific_stages[j] == cyclical_stages[i%len(cyclical_stages)]:
                                            tactic_str += possible_specific_tactics[j]
                                    print(cyclical_stages[i%len(cyclical_stages)])
                                    # If it is mapped to last stage, then simply append the technique and tactic to the last stage
                                    if i == index:
                                        current_tactic_sequence[-1].append(tactic_str)
                                        current_technique_sequence[-1].append(current_technique)
                                    else:
                                        current_stage_sequence.append(cyclical_stages[i%len(cyclical_stages)])
                                        current_tactic_sequence.append([tactic_str])
                                        current_technique_sequence.append([current_technique])
                                        last_stage = cyclical_stages[i%len(cyclical_stages)]
                                        print("LAST STAGE: " + last_stage)
                                    mapped = True
                                    break
                            
                
                        
                            
                        
            
            
                
            #     current_branch_tracker = len(current_stage_sequence)
            #     initial_compromise_filled = False
                
            #     if possible_stages[0] == 'Initial Compromise':
            #         # Update the branch tracker that a new branch has started
            #         current_branch_tracker = len(current_stage_sequence)
            #         current_stage_sequence.append('Initial Compromise')
            #         current_technique_sequence.append([current_technique])
            #         current_tactic_sequence.append([current_tactics])
            #         last_stage = 'Initial Compromise'  
            #         initial_compromise_filled = True
                    
            #     else:
            #         # Update the branch tracker that a new branch has started
            #         current_branch_tracker = len(current_stage_sequence)
            #         # Create an empty 'Initial Compromise' stage
            #         current_stage_sequence.append('Initial Compromise')
            #         current_technique_sequence.append([])
            #         current_tactic_sequence.append([])
            #         # Create the following stage
            #         current_stage_sequence.append(possible_stages[0])
            #         current_technique_sequence.append([current_technique])
            #         current_tactic_sequence.append([current_tactics])
            #         last_stage = possible_stages[0]
            
            # # Logic 6: If all of the tactics belongs to the flexible tactics, then fill in the latest stage from the back
            # elif (check_elements(possible_tactics, flexible_tactics)):
            #     current_technique_sequence[-1].append(current_technique)
                
            
                
                
            
                    
                    
                    
            
            #     else:
            #         index = cyclical_stages.index(last_stage)
            #         for i in range(index, index+4):
            #             if cyclical_stages[i%4] in possible_stages:
            #                 current_stage_sequence.append(possible_stages[0])
                            
                    
                    
                    
                
            #     earliest_possible_stage_index = -1
            #     for i in range(len(current_stage_sequence)-1, current_branch_tracker-1, -1):
            #         # then map it to the latest stage
            #         if (len(current_technique_sequence[i]) > 0) and (current_stage_sequence[i] in possible_stages):
            #             current_technique_sequence[i].append(current_technique)
            #             break
            #         # if not, map it to the earliest stage by tracking the earliest possible stage (e.g. if execution is the tactic of the first technique observed and no other stages are filled, map it to the earliest stage aka 'initial compromise)
            #         elif (current_stage_sequence[i] in possible_stages):
            #             earliest_possible_stage_index = i
            #         elif (i == current_branch_tracker):
            #             current_technique_sequence[earliest_possible_stage_index].append(current_technique)
            #             # if current_stage_sequence[earliest_possible_stage_index] == 'Initial Compromise':
            #                 # initial_compromise_filled = True
            #             # if current_stage_sequence[earliest_possible_stage_index] == 'Establish Foothold':
            #                 # establish_foothold_filled = True
                
            
            
                
            # # Else if one of the possible stages is 'Establish Foothold' and it is not filled yet, fill it up
            # # elif ('Establish Foothold' in possible_stages) and not establish_foothold_filled:
            # #     for i in range(current_branch_tracker, len(current_stage_sequence)):
            # #         if current_stage_sequence[i] == 'Establish Foothold':
            # #             current_technique_sequence[i].append(current_technique)
            # #             establish_foothold_filled = True
            # #             break
                    
        
            # # If not, prioritize the specific tactics and go to the next closest stage
            # else:
            #     possible_tactics_np_array = np.array(possible_tactics)
            #     flexible_tactics_np_array = np.array(flexible_tactics)
            #     # FOCUS ON THE LESS FLEXIBLE TACTICS: Fill up Persistence/Privilege Escalation/Lateral Movement if not filled 
            #     # Note: Exfiltration/Impact won't come here because those will fall above
            #     difference = np.setdiff1d(possible_tactics_np_array, flexible_tactics_np_array)
            #     last_stage = current_stage_sequence[-1]
                
            #     # if previous stage is initial compromise (means it's filled), then check if it's establish foothold, if not, move to cyclical zone and fill in the earliest possible
            #     # A new branch should not be created if initial compromise is one of the multiple stages possible. Because it's 'MULTIPLE STAGES', hence this means there are other stages they can fill.
            #     if (last_stage == 'Initial Compromise'):
            #         map_to_est_foothold = False
            #         for i in difference:
            #             if 'Establish Foothold' in tactic_lifecycle_mapping[i]:
            #                 map_to_est_foothold = True
                            
            #         if map_to_est_foothold:
            #             current_stage_sequence.append('Establish Foothold')
            #             current_technique_sequence.append([current_technique])
            #             map_to_est_foothold = False
                        
                                    
            #     # if previous stage is establish foothold and it's filled, then check if it's persistence, if persistence, stick it to establish foothold, else, move on to next stage
            #     elif (last_stage == 'Establish Foothold'):
            #         for i in difference:
            #             # the general classes wouldn't have fallen here because they have been removed above
            #             if 'Establish Foothold' in tactic_lifecycle_mapping[i]:
            #                 current_technique_sequence[-1].append(current_technique)
            #                 break
                            
                        
                        
            #     # if previous stage is cyclical stages, then prioritize the more specific tactics that belongs to the cyclical zone and fill the earliest possible
            #     else:
                    
            #         # get all the possible stages
            #         possible_stages_in_difference = []
            #         for tactic in difference:
            #             current_possible_stages = tactic_lifecycle_mapping[tactic]
            #             for i in range(len(current_possible_stages)):
            #                 possible_stages_in_difference.append(current_possible_stages[i])
                        
            #         # Get the position of the last existing stage in the cyclical zone
            #         index = cyclical_stages.index(last_stage)
                        
            #         for i in range(index, index+4):
            #             if cyclical_stages[i%4] in possible_stages_in_difference:
            #                 if i == index:
            #                     current_technique_sequence[-1].append(current_technique)
            #                     break
            #                 else:
            #                     current_stage_sequence.append(cyclical_stages[i%4])
            #                     current_technique_sequence.append([current_technique])
            #                     break
                            
            #                 # if previous stage is complete mission, then branch out aka just add initial access and establish foothold, then let the graph drawing function  to drop the empty portion.
                            
                                    
                                
                        
                        
                
          
    print("======================")
    print(current_stage_sequence)
    print(current_tactic_sequence)
    print(current_technique_sequence)
    print("======================")
    generate_graph(current_stage_sequence, current_tactic_sequence, current_technique_sequence)
    
    return

    


            
                
            
if __name__ == "__main__":
    attack_lifecycle_mapping(sample)
        