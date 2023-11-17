##################################################################################################
# IoC (csv) to Yara (yar) Converter for Colab
# Author = Alexander Alexandrov
# Last edited Nov 17, 2023
##################################################################################################
##################################################################################################
##Description: 
#
# If you have many Sophos IoC CSV files in one directory and you want to convert all of them to 
# YARA rules, you can modify the script to loop through all CSV files in the directory and 
# generate YARA rules for each file.
#
# Replace /path/to/sophos_ioc_files/ with the actual path to your directory containing Sophos 
# IoC CSV files. This script will process all CSV files in the specified directory and generate
# corresponding YARA rules. 

# The resulting YARA rules will be saved in the specified output directory (/content/yara_rules/).
###############################################################################################vv

import csv
import os
import re

def clean_indicator(indicator):
    # Remove non-alphanumeric characters
    return re.sub(r'[^a-zA-Z0-9]', '', indicator)

def convert_to_yara(ioc_type, data, note):
    cleaned_data = clean_indicator(data)
    rule_name = f"Sophos_{ioc_type}_{cleaned_data}"

    # Constructing the YARA rule
    yara_rule = f'''
    rule {rule_name}
    {{
        meta:
            description = "{note}"
        strings:
            $ioc = "{data}"
        condition:
            {ioc_type} == $ioc
    }} 
'''
    
    return yara_rule

def convert_sophos_iocs_to_yara(input_directory, output_directory):
    # Create the YARA rules directory if it doesn't exist
    os.makedirs(output_directory, exist_ok=True)

    # Loop through all CSV files in the input directory
    for csv_file_name in os.listdir(input_directory):
        if csv_file_name.endswith('.csv'):
            csv_file_path = os.path.join(input_directory, csv_file_name)

            with open(csv_file_path, 'r') as csv_file:
                csv_reader = csv.DictReader(csv_file)

                for row in csv_reader:
                    ioc_type = row['Indicator_type']
                    data = row['Data']
                    note = row['Note']

                    yara_rule = convert_to_yara(ioc_type.lower(), data, note)

                    # Save the YARA rule to a file
                    output_file_path = os.path.join(output_directory, f'Sophos_{ioc_type}_{clean_indicator(data)}.yar')
                    with open(output_file_path, 'w') as output_file:
                        output_file.write(yara_rule)

# Specify the input directory containing Sophos IoC CSV files
input_directory = '/path/to/sophos_ioc_files/'  # Replace with the actual path

# Specify the output directory for YARA rules
output_directory = '/content/yara_rules/'

# Convert Sophos IoCs to YARA rules
convert_sophos_iocs_to_yara(input_directory, output_directory)
