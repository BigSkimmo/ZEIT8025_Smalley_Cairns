# This script serves to parse javascript files and extract feature vectors for use in machine learning
# It is modelled to replicate and validate the findings of Likarish, Jung, & Jo in their paper titled
# 'Obfuscated Malicious Javascript Detection using Classification Techniques'. The feature vectors are:
#
# 01: Length in characters 		    	The length of the script in characters.
# 02: Avg. Characters per line 	    	The avg. number of characters on each line.
# 03: Num of lines 				    	The number of newline characters in the script.
# 04: Num of strings 					The number of strings in the script.
# 05: Num of unicode symbols 			The number of unicode characters in the script.
# 06: Num of hex or octal numbers 	    A count of the numbers represented in hex or octal.
# 07: % human readable 					We judge a word to be readable if it is > 70% alphabetical, has
# 								    	20% < vowels < 60%, is less than 15 characters long, and does not
# 								    	contain > 2 repetitions of the same character in a row.
# 08: % whitespace 				    	The percentage of the script that is whitespace.
# 09: Num of methods called 			The number of methods invoked by the script.
# 10: Avg. string length 				The average number of characters per string in the script.
# 11: Avg. argument length 		    	The average length of the arguments to a method, in characters.
# 12: Num of comments 			    	The number of comments in the script.
# 13: Avg. comments per line 			The number of comments over the total number of lines in the script.
# 14: Num of words 					    The number of “words” in the script where words are delineated by
# 									    whitespace and javascript symbols (for example, arithmetic operators).
# 15: % words not in comments 			The percentage of words in the script that are not commented out.
#
# This script was written by z5195413 Simon Smalley and z5087415 Lachlan Cairns for ZEIT8025 - Reverse Engineering Malware

import os
import re
import csv
import concurrent.futures
import time

# Path to folder containing javascript files
target_folder_path = "C:\\Users\\Simmo\\Desktop\\benign"

# Output CSV location
output_file_loc = "E:\\benign.csv"

# Are these benign files or malicious files (0 = benign, 1 = malicious)
malicious = 0

# Prepare the first line of the output
fields = ['charLen','avgChar','numLines','numStrings','numUnicode','numHexOct','pcHuman','pcWhitespace','numMethods','avgString','avgArglen','numComments','avgCPL','numWords','pcWNC','malicious']
with open(output_file_loc, 'w+', newline='') as outfile:
    write = csv.writer(outfile)
    write.writerow(fields)
    outfile.close()

def process(input_file):
    # --------------------------------------------------------- #
    #                       CHARACTERS                          #
    # --------------------------------------------------------- #
    # Read the file in characters to get char specific features
    file = open(input_file, encoding="ISO-8859-1").read()

    # 01: Length in characters (len_chars) - don't process this file if the file is empty
    len_chars = len(file)
    if len_chars == 0:
        return None

    # 04: Num of strings (num_strings)
    string_regex_one = r"""['].*?[']"""
    string_regex_two = r"""["].*?["]"""
    string_list = re.findall(string_regex_one, file)
    string_list.append([i for i in re.findall(string_regex_two, file)])
    num_strings = len(string_list)

    # 10: Average string length (avg_strlen)
    avg_strlen = 0
    for string in string_list:
        avg_strlen += len(string)
    if num_strings > 0:     # Catch divide by zero
        avg_strlen = round(avg_strlen / num_strings, 4)

    # 08: Percentage of whitespace (whitespace_pc) & 05: Number of unicode symbols (num_unicode)
    whitespace_pc = 0
    num_unicode = 0
    for letter in file:
        ascii_code = ord(letter)
        if ascii_code in [9, 10, 11, 12, 13, 32]:
            whitespace_pc += 1
        elif ascii_code > 127:
            num_unicode += 1
    if len_chars > 0:       # Catch divide by zero
        whitespace_pc = 100 * round(float(whitespace_pc / len_chars), 4)

    # 06: Num of hex or octal chars (hex_or_oct_chars)
    hex_regex = r"[0\\][xX][0-9a-fA-F]{2,}"
    oct_regex = r"[0][0-9$]{3}"
    hex_or_oct_chars = 0
    hex_or_oct_chars += len(re.findall(hex_regex, file))
    hex_or_oct_chars += len(re.findall(oct_regex, file))

    # 12: Num of comments (num_comments) - have to make an array here to use later
    multiline_comment_regex = r"/\*.*?\*/"
    inline_comment_regex = r"[^:]//.*"
    comment_list = re.findall(multiline_comment_regex, file, re.DOTALL)
    comment_list_2 = re.findall(inline_comment_regex, file)
    comment_list += comment_list_2
    num_comments= len(comment_list)

    # --------------------------------------------------------- #
    #                           WORDS                           #
    # --------------------------------------------------------- #
    # Create a list of the 'words' (strings separated by whitespace and javascript symbols)
    word_list = list(filter(None, re.split('[^a-zA-Z0-9]', file)))

    # 14: Num of words (num_words)
    num_words = len(word_list)

    # 07: % human readable (pc_human) & 15 % words not in comments (words_not_comments)
    human_readable = 0
    pc_human = 0
    words_not_comments = 0
    for word in word_list:
        alphacount = 0
        vowelcount = 0
        if 1 < len(word) < 15:
            for letter in range(0,len(word)):
                if letter > 1 and word[letter] == word[letter-1] and word[letter] == word[letter-2]:
                    continue
                if word[letter].isalpha():
                    alphacount += 1
                if word[letter] in ['a','e','i','o','u']:
                    vowelcount += 1
        else:
            continue
        if alphacount / len(word) > 0.7 and 0.2 <= vowelcount / len(word) <= 0.6:
            human_readable += 1

    comment_words = []
    for comment in comment_list:
        for comment_word in list(filter(None, re.split('[^a-zA-Z0-9]', comment))):
            comment_words.append(comment_word)

    if num_words > 0:  # Catch divide by zero
        pc_human = 100 * round(human_readable / num_words, 4)
        words_not_comments = round(abs((len(comment_words) / num_words)-100),4)

    # --------------------------------------------------------- #
    #                          LINES                            #
    # --------------------------------------------------------- #
    # Read the file in lines to get the line specific features
    file = open(os.path.join(target_folder_path, input_file), encoding="ISO-8859-1").readlines()

    # 03: Number of lines (num_lines)
    num_lines = len(file)

    # 02: Average characters per line (avg_char_line) & 13: Avg. comments per line (comments_per_line)
    avg_char_line = 0
    comments_per_line = 0
    if num_lines > 0:       # Catch divide by zero
        avg_char_line = round(len_chars / num_lines,4)
        comments_per_line = round(num_comments / num_lines, 4)

    # 9: Number of methods called (num_methods) & 11: Avg. argument length (avg_arglen)
    avg_arglen = 0
    method_regex = r"[0-9a-zA-Z]{1,}?\(.*?\)"
    arg_regex = r"\((.*?)\)"
    methods = []
    for line in file:
        if '(' in line and ')' in line:
            if len(line) > 20000:       # Need to put a limit on lines for this regex. Even using non-greedy regex this causes
                continue                # catastophic backtrace in long strings. If a line is >20k, its obfuscation anyway.
            for i in re.findall(method_regex, line):
                methods.append(i)
    for find in methods:
        if find.startswith('if('):
            methods.remove(find)
        else:
            avg_arglen += len(re.search(arg_regex,find).group(1))
    num_methods = len(methods)
    if num_methods > 0:  # Catch divide by zero
        avg_arglen = round(avg_arglen / len(methods), 4)

    # --------------------------------------------------------- #
    #                         OUTPUT                            #
    # --------------------------------------------------------- #
    outlist = [len_chars, avg_char_line, num_lines, num_strings, num_unicode, hex_or_oct_chars, pc_human, whitespace_pc, num_methods, avg_strlen, avg_arglen, num_comments, comments_per_line, num_words, words_not_comments, malicious]

    outfile = open(output_file_loc, 'a', newline='')
    write = csv.writer(outfile)
    write.writerow(outlist)
    outfile.close()

    return outlist


# Process metrics
start_time = time.time()

# Create the iterable for thread pool
folder_list = []
for folder in os.listdir(target_folder_path):
    folder_list.append(os.path.join(target_folder_path, folder))

folder_list_len = len(folder_list)

# Main loop over files
print("Commencing processing...")
print("Number of subfolders of 100 scripts:", folder_list_len)

for subfolder in folder_list:
    main_output_list = []
    file_list = []
    folder = os.path.join(target_folder_path, subfolder)
    for file in os.listdir(folder):
        file_list.append(os.path.join(folder,file))

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for infile in file_list:
            futures.append(executor.submit(process, input_file=infile))
        for future in concurrent.futures.as_completed(futures):
            main_output_list.append(future.result())
            executor.shutdown()


    print('Processed folder:',subfolder)

print("Processing complete. Time taken:", round(time.time() - start_time,2), 'seconds')
print("Complete.")
