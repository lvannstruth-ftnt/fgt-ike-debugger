import os
import re
import pandas as pd
from tabulate import tabulate
#version 1
# change1
# Specify the file name this will be an environment variable later 
file_name = "IKE_Log_combined_all.txt"
# IKE_LOG_V2_PSK.txt
# IKE_LOG_V2_Mismatch.txt
# IKE_SAMPLE_LOG.txt
# IKE_LOG_V2
# IKE_LOG_PFS_mismatch.txt
# IKE_LOG_V2_Partial_selector.txt
# IKE_LOG_V2_ph_2_TS_mismatch_responder.txt
# IKE_LOG_V2_ph_2_TS_mismatch_initiator.txt
# IKE_Log_combined_all.txt
# array to store sentencs to display to the user
analysis_output = []

def read_file(filename):
    # Get the directory of the current script
    current_directory = os.path.dirname(os.path.abspath(__file__))
    
    # Construct the full file path
    file_path = os.path.join(current_directory, filename)
    
    try:
        # Open and read the file
        with open(file_path, 'r') as file:
            content = file.read()
            return str(content)
    except FileNotFoundError:
        print(f"The file '{filename}' was not found in the current directory.")
    except Exception as e:
        print(f"An error occurred: {e}")

def ike_parser(text):
    """
    Finds and prints lines containing the phrase 'SA proposal chosen' in the given text.

    :param text: The multi-line string to search through.
    """
    comes_line_phase_1 = None
    ike_phase_1_type = None
    comes_line = None
    fail_line = None
    lines = text.splitlines()
    for i, line in enumerate(lines):

        # Phase-1 check
        if "SA proposal chosen" in line and "no SA proposal chosen" not in line:
            _phase_1_check(i,line,lines)
        # phase-2 check
        if "added IPsec SA" in line:
            _phase_2_check(i,line,lines)
        #Check for Phase-1 Negotiation failures
        if "negotiation failure" in line or "no proposal chosen" in line:
            fail_line=i
            if comes_line_phase_1:
                Ike_param = _extract_lines(lines, comes_line, fail_line)
                _phase_1_2_mismatch(i,line,comes_line_phase_1,ike_phase_1_type,Ike_param)
                comes_line_phase_1 = None
                ike_phase_1_type = None
                comes_line = None
                fail_line = None
        
        if "PSK auth failed: probable pre-shared key mismatch" in line:
            if comes_line_phase_1:
                _phase_1_psk_fail(i,line,comes_line_phase_1,ike_phase_1_type)
                comes_line_phase_1 = None
                ike_phase_1_type = None
                comes_line = None
                fail_line = None
        
        # Grabs the connection details for the phase-1 mismatch
        if "comes" in line:
            comes_line_phase_1 = line
            comes_line = i + 3
            if i + 1 < len(lines):
                ike_phase_1_type = lines[i + 1]

            # _phase_1_mismatch_V1(i,line,lines)
        
        if "phase2 matched by subset" in line:
            _phase_2_subset(i,line,lines)

        if "failed to match peer selectors" in line:
            fail_line=i
            if comes_line_phase_1:
                _phase_2_ts_mismatch_responder(i,line,lines,comes_line_phase_1,ike_phase_1_type)
                comes_line_phase_1 = None
                ike_phase_1_type = None
                comes_line = None
                fail_line = None
                _phase_2_ts_mismatch_initiator
        
        if 'TS_UNACCEPTABLE' in line:
            fail_line=i
            if comes_line_phase_1:
                _phase_2_ts_mismatch_initiator(i,line,lines,comes_line_phase_1,ike_phase_1_type)
                comes_line_phase_1 = None
                ike_phase_1_type = None
                comes_line = None
                fail_line = None

def _extract_lines(lines, start_line, end_line):
    input_string = "\n".join(lines[start_line-1:end_line])
    split_keyword = "my proposal"
    split_index = input_string.find(split_keyword)
    
    # Split the string into two parts
    if split_index != -1:
        part1 = input_string[:split_index].strip()
        part2 = input_string[split_index:].strip()
        return [part1, part2]
    else:
        return None, None



# Phase-1 check helper function
def _phase_1_check(i,line,lines):
    start_index = line.index("SA proposal chosen")
    sa_proposal = line[start_index:]
    # Also get the connection for which SA proposal is chosen
    if i + 1 < len(lines):
        conn = lines[i + 1]
        sa_conn = conn.split()[-1]
        analysis_output.append(f'[{str(i+1)}]::'+sa_proposal+' VPN with IP Connection as:'+sa_conn+' is UP for phase-1')

# Phase-2 check helper function
def _phase_2_check(i,line,lines):
    if i + 1 < len(lines):
        phase_2_log = lines[i + 1].strip()
        start_index = phase_2_log.index("IKE connection add")
        phase_2_conn = (phase_2_log[start_index:]).split()[-1]
        analysis_output.append(f'[{str(i+1)}]::'+'VPN with IP Connection as -> '+phase_2_conn+' is UP for phase-2')

# Phase-1/2 mismatch helper function
def _phase_1_2_mismatch(i,line,comes_line_phase_1,ike_phase_1_type,Ike_param):
    Ike_type = ''
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    mismatch_param = ''    
    phase_2=False
    def compare_ike_proposals(string1, string2):
        param = []
        # Regular expression to extract the relevant IKE parameters
        pattern = r"type=([A-Z_]+),\s*val=([A-Za-z0-9_]+)(?:,\s*key-len=(\d+))?"

        # Extract the parameters from both strings
        def extract_parameters(s):
            # Clean up extra whitespace and capture parameters
            return re.findall(pattern, s.replace("\n", " ").replace("\r", " ").strip())

        params1 = extract_parameters(string1)
        params2 = extract_parameters(string2)

        mismatched_params = []

        # Compare parameters
        for p1, p2 in zip(params1, params2):
            if p1 != p2:
                mismatched_params.append((p1, p2))

        if mismatched_params:
            for p1, p2 in mismatched_params:
                # print(f"Parameter 1: {p1} | Parameter 2: {p2}")
                param.append(f"Incoming: {p1} | local: {p2}")
        return " ,, ".join(param)
    
    # Statement to check for phase-1 mismatch and also for phase-2 diff
    if Ike_param[0] is not None and Ike_param[1] is not None:
        mismatch_param = compare_ike_proposals(Ike_param[0], Ike_param[1])
        
        # check pfs disable on remote peer 
        if ("PFS is disabled" in Ike_param[0] and "PFS is disabled" not in Ike_param[1]):
            if "IKEv1" in ike_phase_1_type:
                Ike_type = "IKE-V1"
                analysis_output.append(f'[{str(i+1)}]::'+' Negotiation Failure for '+f'{Ike_type}'+ ' Phase-2 connection '+failure_message.split()[1]+' due to PFS being disabled in remote peer')
            if "IKEv2" in ike_phase_1_type:
                Ike_type = "IKE-V2"
                analysis_output.append(f'[{str(i+1)}]::'+' Negotiation Failure for '+f'{Ike_type}'+ ' Phase-2 connection '+failure_message.split()[1]+' due to PFS being disabled in remote peer')
            # turn on phase_2 flag
            phase_2=True
            
        # check pfs disable on local peer 
        if ("PFS is disabled" in Ike_param[1] and "PFS is disabled" not in Ike_param[0]):
            if "IKEv1" in ike_phase_1_type:
                Ike_type = "IKE-V1"
                analysis_output.append(f'[{str(i+1)}]::'+' Negotiation Failure for '+f'{Ike_type}'+ ' Phase-2 connection '+failure_message.split()[1]+' due to PFS being disabled in local peer')
            if "IKEv2" in ike_phase_1_type:
                Ike_type = "IKE-V2"
                analysis_output.append(f'[{str(i+1)}]::'+' Negotiation Failure for '+f'{Ike_type}'+ ' Phase-2 connection '+failure_message.split()[1]+' due to PFS being disabled in local peer')
            # turn on phase_2 flag
            phase_2=True
    
    # only hit this statement if phase_2 remains false
    if "IKEv1" in ike_phase_1_type and phase_2==False:
        Ike_type = "IKE-V1"
        analysis_output.append(f'[{str(i+1)}]::'+' Negotiation Failure for '+f'{Ike_type}'+ ' Connection '+failure_message.split()[1]+' With mismatch as \n'+str(parse_to_table(mismatch_param)))

    # only hit this statement if phase_2 remains false
    if "IKEv2" in ike_phase_1_type and phase_2==False:
        Ike_type = "IKE-V2"
        analysis_output.append(f'[{str(i+1)}]::'+' Negotiation Failure for '+f'{Ike_type}'+ ' Connection '+failure_message.split()[1]+' With mismatch as \n'+str(parse_to_table(mismatch_param)))


def _phase_1_psk_fail(i,line,comes_line_phase_1,ike_phase_1_type):
    Ike_type = ''
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    if "IKEv1" in ike_phase_1_type:
        Ike_type = "IKE-V1"
        analysis_output.append(f'[{str(i+1)}]::'+' PSK Mismatch for '+f'{Ike_type}'+ ' Connection '+failure_message.split()[1]+' Please check PSK ')
    if "IKEv2" in ike_phase_1_type:
        Ike_type = "IKE-V2"
        analysis_output.append(f'[{str(i+1)}]::'+' PSK Mismatch for '+f'{Ike_type}'+ ' Connection '+failure_message.split()[1]+' Please check PSK ')

def _phase_2_subset(i,line,lines):
    accepted_proposals = ''
    if i + 1 < len(lines):
        accepted_proposals=lines[i + 2]+'\n'+lines[i + 3]
    analysis_output.append(f'[{str(i+1)}]:: phase2 matched by subset. Accepted proposals are: \n' + accepted_proposals + '\n advised to use matching selectors and not sub/super sets')

# phase_2 selector mismatch on responder
def _phase_2_ts_mismatch_responder(i,line,lines,comes_line_phase_1,ike_phase_1_type):
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    ts = ''
    if i + 1 < len(lines):
        ts=lines[i - 2]+'\n'+lines[i - 3]
        if "IKEv1" in ike_phase_1_type:
            Ike_type = "IKE-V1"
            analysis_output.append(f'[{str(i+1)}]:: phase2 selector mismatch for incoming traffic selectors \n' + ts + '\n advised to check traffic selectors on initiatior for \n' + f'{Ike_type}' + ' connection ' + f'{failure_message}')
        if "IKEv2" in ike_phase_1_type:
            Ike_type = "IKE-V2"
            analysis_output.append(f'[{str(i+1)}]:: phase2 selector mismatch for incoming traffic selectors \n' + ts + '\n advised to check traffic selectors on initiatior for \n' + f'{Ike_type}' + ' connection ' + f'{failure_message}')

# phase_2 selector mismatch on initiator
def _phase_2_ts_mismatch_initiator(i,line,lines,comes_line_phase_1,ike_phase_1_type):
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    if "IKEv1" in ike_phase_1_type:
        Ike_type = "IKE-V1"
        analysis_output.append(f'[{str(i+1)}]:: phase2 selector mismatch \n advised to check traffic selectors on responder for \n' + f'{Ike_type}' + ' connection ' + f'{failure_message}')
    if "IKEv2" in ike_phase_1_type:
        Ike_type = "IKE-V2"
        analysis_output.append(f'[{str(i+1)}]:: phase2 selector mismatch \n advised to check traffic selectors on responder for \n' + f'{Ike_type}' + ' connection ' + f'{failure_message}')
    

def parse_to_table(data_string):
    # Split the string into individual comparisons
    entries = data_string.split(",, ")

    # Initialize lists to store parsed data
    incoming_data = []
    local_data = []

    # Parse each entry and extract incoming and local information
    for entry in entries:
        incoming_part, local_part = entry.split(" | ")

        # Extract the key and value parts for incoming and local
        incoming_key, incoming_val1, incoming_val2 = eval(incoming_part.split(": ")[1])
        local_key, local_val1, local_val2 = eval(local_part.split(": ")[1])

        # Append the parsed values to the respective lists
        incoming_data.append([incoming_key, incoming_val1, incoming_val2])
        local_data.append([local_key, local_val1, local_val2])

    # Create DataFrames for Incoming and Local data
    incoming_df = pd.DataFrame(incoming_data, columns=["Key", "Value1", "Value2"])
    local_df = pd.DataFrame(local_data, columns=["Key", "Value1", "Value2"])

    # Combine Incoming and Local data into a single table
    combined_df = pd.concat(
        [incoming_df.add_prefix("Incoming_"), local_df.add_prefix("Local_")], axis=1
    )

    # Pretty-print the table
    return tabulate(combined_df, headers="keys", tablefmt="grid")
    
# Log file in cache
ike_log = read_file(file_name)

ike_parser(ike_log)

# Loop through the array to print the analysis
for output in analysis_output:
    print(output)



