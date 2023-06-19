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
from MitreTrial import *

sample = ['T1189', 'T1651', 'T1189', 'T1087', 'T1098', 'T1020', 'T1189', 'T1548', 'T1134', 'T1557', 'T1210', 'T1560', 'T1071', 'T1020', 'T1531']
# sample = ['T1189', 'T1651', 'T1189', 'T1087', 'T1098', 'T1020', 'T1189']
# sample = ['T1189', 'T1651' , 'T1531']

# Create a dictionary of which part of the attack lifecycle each tactic belong to
# <<'Initial Access' : ['Initial Compromise']>> means the tactic 'Initial Access' belongs to the attack lifecycle stage called 'Initial Compromise' 
tactic_lifecycle_mapping = {
    'Initial Access'        : ['Initial Compromise'],
    'Execution'             : ['Initial Compromise','Establish Foothold', 'Escalate Privilege', 'Internal Reconnaissance', 'Move Laterally'],
    'Persistence'           : ['Establish Foothold', 'Maintain Presence'],
    'Privilege Escalation'  : ['Escalate Privilege'],
    'Defense Evasion'       : ['Initial Compromise','Establish Foothold', 'Escalate Privilege', 'Internal Reconnaissance', 'Move Laterally'],
    'Credential Access'     : ['Initial Compromise','Establish Foothold', 'Escalate Privilege', 'Internal Reconnaissance', 'Move Laterally'],
    'Discovery'             : ['Internal Reconnaissance'],
    'Lateral Movement'      : ['Move Laterally'],
    'Collection'            : ['Complete Mission'],
    'Command and Control'   : ['Establish Foothold', 'Escalate Privilege', 'Internal Reconnaissance', 'Move Laterally'],
    'Exfiltration'          : ['Complete Mission'],
    'Impact'                : ['Complete Mission']
    }

# Create a requirement list
# << 'Maintain Presence' : ['Initial Compromise', 'Establish Foothold'] >> means before the attack lifecycle stage, there must be the stages 'Initial Compromise' and 'Establish Foothold'
# requirement = {
#     'Maintain Presence'     : ['Initial Compromise', 'Establish Foothold'],
#     'Escalate Privilege'    : ['Initial Compromise', 'Establish Foothold'],
#     'Move Laterally'        : ['Initial Compromise', 'Establish Foothold'],
#     'Internal Recon'        : ['Initial Compromise', 'Establish Foothold'],
#     'Impact'                : ['Initial Compromise', 'Establish Foothold']
#     }

# initial_sequence = ['Initial Compromise', 'Establish Foothold', 'Maintain Presence', 'Escalate Privilege', 'Move Laterally', 'Internal Recon', 'Complete Mission']




def generate_string(stage, technique_list):
    result = '<f0> ' + stage + ' | {<f1> '
    if (len(technique_list) == 0):
        result += ('Missing compulsory stage')
    else:
        for technique in technique_list:
            result += (technique + '\\n')
    result += '}'
    return result

                
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
                G.add_edge(str(i-1), str(j+1))
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
            

def check_elements(array1, array2):
    for element in array1:
        if element not in array2:
            return False
    return True













def attack_lifecycle_mapping(technique_list_raw):

    # Place all techniques in a FIFO queue to process
    technique_list = queue.Queue()
    for x in sample:
        technique_list.put(x)
        
        
    # Prepare unique tactic technique list
    df = get_technique_df()
    tactic_technique_combi = get_unique_tactic_technique_pair(df)
        
    
    
    
    
    current_stage_sequence = ['Initial Compromise', 'Establish Foothold']
    current_technique_sequence = [[],[]]
    current_branch_tracker = 0          # Track initial position of current branch
    last_stage = ''
    initial_compromise_filled = False
    establish_foothold_filled = False
    
    compulsory_stages = ['Initial Compromise','Establish Foothold']
    cyclical_stages = ['Escalate Privilege', 'Internal Reconnaissance', 'Move Laterally', 'Maintain Presence']
    #flexible_techniques are those that belong only to these classes
    flexible_tactics = ['Execution', 'Defense Evasion', 'Credential Access', 'Command and Control']
    
    # Process each element one by one and add it to graph
    while not technique_list.empty():
        
        # Get the first technique
        current_technique = technique_list.get()
        # print(current_technique)
        
        # Get it's respective tactics
        current_tactics = tactic_technique_combi[tactic_technique_combi["parent_ID"] == current_technique].tactics.iloc[0]
        # print(current_tactics)
        
        # Get it's respective attack lifecycle stage
        # Look at all tactics belonging to the technique
        possible_stages = []
        possible_tactics = []
        
        for tactic in current_tactics:
            current_stages = tactic_lifecycle_mapping[tactic]
            for i in range(len(current_stages)):
                possible_tactics.append(tactic)
                possible_stages.append(current_stages[i])
                
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
        if (len(possible_stages) == 1):
            found = False
            
            # If it is 
            # 1) initial compromise and initial compromise in that branch is not filled
            # 2) Establish Foothold and est. foothold in that branch is not filled (no such tactic as of June 2023)
            # 3) or any other stages
            if (possible_stages[0] != 'Initial Compromise' and possible_stages[0] != 'Establish Foothold') or (possible_stages[0] == 'Initial Compromise' and not initial_compromise_filled) or (possible_stages[0] == 'Establish Foothold' and not establish_foothold_filled):
                for i in range(current_branch_tracker, len(current_stage_sequence)):
                # If the stage exist already, add it to that stage 
                    if current_stage_sequence[i] == possible_stages[0]:
                        current_technique_sequence[i].append(current_technique)
                        found = True
                        if possible_stages[0] == 'Initial Compromise':
                            initial_compromise_filled = True
                        if possible_stages[0] == 'Establish Foothold':
                            establish_foothold_filled = True
                        break
                # If the stage cannot be found in the current sequence
                if not found:
                    current_stage_sequence.append(possible_stages[0])
                    current_technique_list = []
                    current_technique_list.append(current_technique)
                    current_technique_sequence.append(current_technique_list)
                    
            # If not start a new branch (branch only increase when we move from stages other than 'Initial Compromise' and 'Establish Foothold' to 'Initial Compromise')
            else:
                current_branch_tracker = len(current_stage_sequence)
                empty_array = []
                
                print("+++++++++++++++++++++++++++++++++++++++++++++++++++")
                current_stage_sequence.append('Initial Compromise')
                initial_compromise_filled = False
                current_technique_sequence.append(empty_array)
                if possible_stages[0] == 'Initial Compromise':
                    current_technique_sequence[-1].append(current_technique)
                    initial_compromise_filled = True
                    empty_array = []
                
                current_stage_sequence.append('Establish Foothold')
                establish_foothold_filled = False
                current_technique_sequence.append(empty_array)
                if possible_stages[0] == 'Establish Foothold':
                    current_technique_sequence[-1].append(current_technique)
                    establish_foothold_filled = True
                print("---------------------------------------------------")
           
        # If the technique belongs to multiple stages of the attack lifecycle
        # Fill up based on the last stage or earliest possible stage if there is no last stage (Defense evasion, Execution and Command and Control)
        else:
            
            # If all of the tactics belongs to the flexible tactics
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
            elif ('Establish Foothold' in possible_stages) and not establish_foothold_filled:
                for i in range(current_branch_tracker, len(current_stage_sequence)):
                    if current_stage_sequence[i] == 'Establish Foothold':
                        current_technique_sequence[i].append(current_technique)
                        establish_foothold_filled = True
                        break
                    
            # Else fill the earliest cyclical zone
            else:
                added = False
                for stage in possible_stages:
                    # If possible stage contains 'Initial Compromise' or 'Establish Foothold', ignore, cause they are filled
                    if stage == 'Initial Compromise' or stage == 'Establish Foothold' or stage == 'Complete Mission':
                        continue
                    else: 
                        last_stage = current_stage_sequence[-1]
                        if (last_stage != 'Initial Compromise') and (last_stage != 'Establish Foothold'):
                            index = cyclical_stages.index(last_stage)
                        else:
                            index = 0
                        # move across the 4 stages in the cyclical stages to find the next stage cloest to previous stage
                        for i in range(4):
                            next_stage_index = (index + i + 1)%4
                            next_stage = cyclical_stages[next_stage_index]
                            # if found the next_stage within the possible stages
                            if next_stage in possible_stages:
                                # find the position in the current sequence
                                found = False
                                position = 0
                                for i in range(current_branch_tracker, len(current_stage_sequence)):
                                    if current_stage_sequence[i] == next_stage:
                                        found == True
                                        position = i
                                        
                                if found:
                                    current_technique_sequence[position].append(current_technique)
                                    added = True
                                    break
                                else:
                                    new_technique_array = [current_technique]
                                    current_stage_sequence.append(next_stage)
                                    current_technique_sequence.append(new_technique_array)
                                    added = True
                                    break
                        if added:
                            break
                                    
                                
                        
                        
                
          
    print("======================")
    print(current_stage_sequence)
    print(current_technique_sequence)
    print("======================")
    generate_graph(current_stage_sequence, current_technique_sequence)
    
    return

    


            
                
            
            
        

# current sequence
# 2 compulsory
# 4 cycles (need to establish this)

# current branch tracker (So if branch out, don't go back to OG branch) 1, 6+1, 6+6+1 ...

# If only belong to 1 attack lifecycle, put there
# If belong to more than 1 lifecycle stages, and 1 of it belongs to one of the 2 compulsory, and they are empty, place it at the compulsory
# else, place it in one of the 4 cycles (if it involes more than 1 of the 4 cycle, then go to current sequence and see what is the current stage, either place it at the current stage or the next stage)
# If at one of the 4 and now is initial sequence/establish foothold, branch out
# If at impact and still got more, branch out from the last in the one of the 4
# when branching out, remember to increase the currect branch tracker



#initialize with 2 initial sequences
# at the end, if only 2, means got missing info
# if only got 3 and third one is impact, also got missing info
# if no impact at the very end of the sequence, also got missing info

# if initial access and in front got existing branch and it's not initial access, pop a new branch
# once impact, link back to earlier position called "nearest_to_est_foothold"












# # Example of how to generate graph

# G = pgv.AGraph(strict=False, directed=True)

# G.add_node("1", label='<f0> Initial Access | {<f1> T1234 - Discovery \\n T1234 - Discovery \\n T1234 - Discovery \\n T1234 - Discovery \\n T1234 - Discovery \\n T1234 - Discovery}', shape = "record", color = 'red', fontcolor='red')  # adds node 'a'
# G.add_node("2", label='<f0> Establish Foothold | {<f1> 1234 - Discovery \\n T1234 - Discovery \\n T1234 - Discovery \\n T1234 - Discovery \\n T1234 - Discovery \\n T1234 - Discovery}', shape = "record", color = 'blue', fontcolor='blue')
# G.add_node("3", label='<f0> Maintain Presence | {<f1> T1234 - Discovery \\n T1234 - Discovery \\n}', shape = "record", color = 'green', fontcolor='green')
# G.add_node("4", label='<f0> Control and Command | {<f1> T1234 - Discovery \\n T1234 - Discovery \\n}', shape = "record")
# G.add_node("5", label='<f0> Internal Recon | {<f1> T1234 - Discovery \\n T1234 - Discovery \\n T1234 - Discovery \\n T1234 - Discovery \\n T1234 - Discovery \\n T1234 - Discovery}', shape = "record")
# G.add_node("6", label='<f0> Move Laterally | {<f1> T1234 - Discovery \\n T1234 - Discovery \\n T1234 - Discovery \\n T1234 - Discovery \\n T1234 - Discovery \\n T1234 - Discovery}', shape = "record")
# G.add_node("7", label='<f0> Impact | {<f1> T1234 - Discovery \\n T1234 - Discovery \\n}', shape = "record")
# G.add_node("8", label='<f0> Initial Access | {<f1> T1234 - Discovery 2 \\n T1234 - Discovery 2 \\n T1234 - Discovery 2 \\n T1234 - Discovery 2 \\n T1234 - Discovery \\n T1234 - Discovery}', shape = "record", color = 'red', fontcolor='red')

# G.add_edge("1", "2")  # adds edge 'b'-'c' (and also nodes 'b', 'c')
# G.add_edge("2", "3") 
# G.add_edge("3", "4") 
# G.add_edge("4", "5")
# G.add_edge("5", "6")
# G.add_edge("5", "8")
# G.add_edge("6", "3")
# G.add_edge("6", "7")   

# # G.add_node("initial access1", label="<f0> Initial Access | {<f1> T1234 - Discovery \\\n T1234 - Discovery \\\n T1234 - Discovery}", shape="record")
# # G.add_node("initial access2", label="<f0> text | {<f1> T1234 - Discovery \\\n T1234 - Discovery \\\n T1234 - Discovery}", shape="record")
# # G.add_edge('initial access1', 'initial access2')

# G.layout()  # default to neato
# G.layout(prog="dot")  # use dot

# G.draw("file.png")






# import pydot

# dot_string = """digraph {
#   "Initial Access" [xlabel="Sparks \\n sparks\\n sparks\\n sparks\\n sparks\\n sparks\\n sparks\\n sparks2"] "⚡" [xlabel="Fires \\n Fires \\nFires \\nFires \\nFires \\nFires \\nFires \\n"]
#   "🔥" [xlabel="Fires \\n Fires \\nFires \\nFires \\nFires \\nFires \\nFires \\n"]
#   "A" [xlabel="Fires \\n Fires \\nFires \\nFires \\nFires \\nFires \\nFires \\n"] 
#   "Initial Access" -> "⚡"
#   "⚡"->"A" [xlabel="Sometimes" label="Cause"]
#   "A"->"B"
#   "B"->"🔥"
#   "🔥"->"⚡"
# }"""

# graphs = pydot.graph_from_dot_data(dot_string)
# graph = graphs[0]

# graph.write_png("output.png")