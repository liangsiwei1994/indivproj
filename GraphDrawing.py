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

# Sequence given in https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-320a
sample = ['T1190', 'T1059', 'T1562', 'T1105', 'T1070', 'T1136', 'T1016', 'T1053', 'T1021', 'T1078', 'T1136', 'T1090', 'T1018', 'T1098', 'T1003']
# sample = ['T1190']

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
stages_seq = ['Initial Compromise', 'Establish Foothold', 'Escalate Privilege', 'Internal Reconnaisance', 'Move Laterally', 'Maintain Presence', 'Impact']

# Stages that cannot be missing
compulsory_stages = ['Initial Compromise']

# Stages which can be repeated multiple times in the cycle
cyclical_stages = ['Escalate Privilege', 'Internal Reconnaissance', 'Move Laterally', 'Maintain Presence']

# Tactics that do not belong to a particular stage
flexible_tactics = ['Execution', 'Defense Evasion', 'Credential Access', 'Command and Control']



# Generate label string for each node using the lifecycle stage name and the technique list given
def generate_string(stage, technique_list):
    result = '<f0> ' + stage + ' | {<f1> '
    if (len(technique_list) == 0):
        result += ('Missing compulsory stage')
    else:
        for technique in technique_list:
            result += (technique + ' - ' + get_technique_name(technique) + '\\n')
    result += '}'
    return result


                
# Generate a graph using an array of stages (in sequence) and the techniques involved in each stage
def generate_graph(stages, techniques):
    
    G = pgv.AGraph(strict=False, directed=True)
    
    # Find 2 types of missing info, no middle loop or doesn't end with impact
    if (stages[-1] != 'Complete Mission'):
        stage = 'Complete Mission'
        technique_list = []
        stages.append(stage)
        techniques.append(technique_list)
        
    # If it goes immediately from "Establish Foothold" to "Complete Mission", create a node to indicate that there's missing info
    final_position_checked = 0
    while (final_position_checked != (len(stages)-1)):
        i = 0
        for i in range(len(stages)):
            if (stages[i] == 'Complete Mission' and stages[i-1] == 'Establish Foothold'):
                stages.insert(i, 'Missing Info')
                techniques.insert(i, ['Missing cycle between impact \\n and establish foothold'])
                break
        final_position_checked = i
        
        # print("Final Position Checked: " + str(final_position_checked))
        # print("Stages length: " + str(len(stages)))
        

    
    # Create nodes
    for i in range(len(stages)):
        # print(i)
        # print("Stages length in create nodes: " + str(len(stages)))
        # print(stages)
        # print("Techniques length in create nodes: " + str(len(techniques)))
        # print(techniques)
        # print(stages)
        # print(techniques[i])
        node_label = generate_string(stages[i], techniques[i])
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
        
        print(tactic_technique_combi)
        
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
                    current_tactic_sequence.append([current_tactics])
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
                    current_tactic_sequence.append([current_tactics])
                    last_stage = possible_stages[0]
                    
                    
            # Logic 2: it is an 'Initial Compromise' only class AND ('Initial Compromised' has not been filled in the current branch OR previous stage is 'Initial Compromise')
            # fill up at the 'Initial Compromise' stage of the current branch. Else, create a new branch (Logic 3).
            elif (possible_stages[0] == 'Initial Compromise') and (not initial_compromise_filled or last_stage == 'Initial Compromise'):
                for i in range(current_branch_tracker, len(current_stage_sequence)):
                    if current_stage_sequence[i] == 'Initial Compromise':
                        current_technique_sequence[i].append(current_technique)
                        # Immediately append tactic because there's only 1 tactic
                        current_tactic_sequence[i].append(current_tactics)
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
                                break
                            else:
                                current_stage_sequence.append(cyclical_stages[i%4])
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
                            # If not, create a new stage
                            else:
                                current_stage_sequence.append(possible_stages[0])
                                current_technique_sequence.append([current_technique])
                                current_tactic_sequence.append([current_tactics])
                                last_stage = possible_stages[0]
                
                    
            # Logic 3: If it is an 'Initial Compromise' but there is already 'Initial Compromise' in the current branch AND the previous stage is NOT 'Initial Access', start a new branch.
            else:
                current_branch_tracker = len(current_stage_sequence)
                print("+++++++++++++++++++++++++++++++++++++++++++++++++++")
                current_stage_sequence.append('Initial Compromise')
                current_technique_sequence.append([current_technique])
                print("---------------------------------------------------")
           
            
        # If the technique belongs to multiple stages of the attack lifecycle, then LOOK AT TACTICS
        # Fill up based on the last stage or earliest possible stage if there is no last stage (Defense evasion, Execution and Command and Control)
        else:
            
            # If all of the tactics belongs to the flexible tactics, then fill in the previous stage or the first available stage
            if (check_elements(possible_tactics, flexible_tactics)):
                earliest_possible_stage_index = -1
                mapped = False
                for i in range(len(current_stage_sequence)-1, current_branch_tracker-1, -1):
                    # then map it to the latest stage
                    if (len(current_technique_sequence[i]) > 0) and (current_stage_sequence[i] in possible_stages):
                        current_technique_sequence[i].append(current_technique)
                        break
                    # if not, map it to the earliest stage by tracking the earliest possible stage (e.g. if execution is the tactic of the first technique observed and no other stages are filled, map it to the earliest stage aka 'initial compromise)
                    elif (current_stage_sequence[i] in possible_stages):
                        earliest_possible_stage_index = i
                    elif (i == current_branch_tracker):
                        current_technique_sequence[earliest_possible_stage_index].append(current_technique)
                        # if current_stage_sequence[earliest_possible_stage_index] == 'Initial Compromise':
                            # initial_compromise_filled = True
                        # if current_stage_sequence[earliest_possible_stage_index] == 'Establish Foothold':
                            # establish_foothold_filled = True
                
            
            # If one of the possible stages it can belong to is 'Initial Compromise' and it is not filled yet, fill it up
            elif ('Initial Compromise' in possible_stages) and not initial_compromise_filled:
                for i in range(current_branch_tracker, len(current_stage_sequence)):
                    if current_stage_sequence[i] == 'Initial Compromise':
                        current_technique_sequence[i].append(current_technique)
                        initial_compromise_filled = True
                        break
                
            # Else if one of the possible stages is 'Establish Foothold' and it is not filled yet, fill it up
            # elif ('Establish Foothold' in possible_stages) and not establish_foothold_filled:
            #     for i in range(current_branch_tracker, len(current_stage_sequence)):
            #         if current_stage_sequence[i] == 'Establish Foothold':
            #             current_technique_sequence[i].append(current_technique)
            #             establish_foothold_filled = True
            #             break
                    
        
            # If not, prioritize the specific tactics and go to the next closest stage
            else:
                possible_tactics_np_array = np.array(possible_tactics)
                flexible_tactics_np_array = np.array(flexible_tactics)
                # FOCUS ON THE LESS FLEXIBLE TACTICS: Fill up Persistence/Privilege Escalation/Lateral Movement if not filled 
                # Note: Exfiltration/Impact won't come here because those will fall above
                difference = np.setdiff1d(possible_tactics_np_array, flexible_tactics_np_array)
                last_stage = current_stage_sequence[-1]
                
                # if previous stage is initial compromise (means it's filled), then check if it's establish foothold, if not, move to cyclical zone and fill in the earliest possible
                # A new branch should not be created if initial compromise is one of the multiple stages possible. Because it's 'MULTIPLE STAGES', hence this means there are other stages they can fill.
                if (last_stage == 'Initial Compromise'):
                    map_to_est_foothold = False
                    for i in difference:
                        if 'Establish Foothold' in tactic_lifecycle_mapping[i]:
                            map_to_est_foothold = True
                            
                    if map_to_est_foothold:
                        current_stage_sequence.append('Establish Foothold')
                        current_technique_sequence.append([current_technique])
                        map_to_est_foothold = False
                        
                                    
                # if previous stage is establish foothold and it's filled, then check if it's persistence, if persistence, stick it to establish foothold, else, move on to next stage
                elif (last_stage == 'Establish Foothold'):
                    for i in difference:
                        # the general classes wouldn't have fallen here because they have been removed above
                        if 'Establish Foothold' in tactic_lifecycle_mapping[i]:
                            current_technique_sequence[-1].append(current_technique)
                            break
                            
                        
                        
                # if previous stage is cyclical stages, then prioritize the more specific tactics that belongs to the cyclical zone and fill the earliest possible
                else:
                    
                    # get all the possible stages
                    possible_stages_in_difference = []
                    for tactic in difference:
                        current_possible_stages = tactic_lifecycle_mapping[tactic]
                        for i in range(len(current_possible_stages)):
                            possible_stages_in_difference.append(current_possible_stages[i])
                        
                    # Get the position of the last existing stage in the cyclical zone
                    index = cyclical_stages.index(last_stage)
                        
                    for i in range(index, index+4):
                        if cyclical_stages[i%4] in possible_stages_in_difference:
                            if i == index:
                                current_technique_sequence[-1].append(current_technique)
                                break
                            else:
                                current_stage_sequence.append(cyclical_stages[i%4])
                                current_technique_sequence.append([current_technique])
                                break
                            
                            # if previous stage is complete mission, then branch out aka just add initial access and establish foothold, then let the graph drawing function  to drop the empty portion.
                            
                                    
                                
                        
                        
                
          
    print("======================")
    print(current_stage_sequence)
    print(current_technique_sequence)
    print("======================")
    generate_graph(current_stage_sequence, current_technique_sequence)
    
    return

    


            
                
            
if __name__ == "__main__":
    attack_lifecycle_mapping(sample)
        