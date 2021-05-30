# This script serves to parse javascript files and extract feature vectors for use in machine learning
# It is modelled to replicate and validate the findings of Likarish, Jung, & Jo in their paper titled
# 'Obfuscated Malicious Javascript Detection using Classification Techniques'. The feature vectors are:
#
# 01: Length in characters 				The length of the script in characters.
# 02: Avg. Characters per line 			The avg. number of characters on each line.
# 03: Num of lines 						The number of newline characters in the script.
# 04: Num of strings 					The number of strings in the script.
# 05: Num of unicode symbols 			The number of unicode characters in the script.
# 06: Num of hex or octal numbers 		A count of the numbers represented in hex or octal.
# 07: % human readable 					We judge a word to be readable if it is > 70% alphabetical, has
# 										20% < vowels < 60%, is less than 15 characters long, and does not
# 										contain > 2 repetitions of the same character in a row.
# 08: % whitespace 						The percentage of the script that is whitespace.
# 09: Num of methods called 			The number of methods invoked by the script.
# 10: Avg. string length 				The average number of characters per string in the script.
# 11: Avg. argument length 				The average length of the arguments to a method, in characters.
# 12: Num of comments 					The number of comments in the script.
# 13: Avg. comments per line 			The number of comments over the total number of lines in the script.
# 14: Num of words 						The number of “words” in the script where words are delineated by
# 										whitespace and javascript symbols (for example, arithmetic operators).
# 15: % words not in comments 			The percentage of words in the script that are not commented out.
#
# This script was written by z5195413 Simon Smalley and z5087415 Lachlan Cairns for ZEIT8025 - Reverse Engineering Malware

import os
import re
import csv
import concurrent.futures
import time
import sys
import math

# Path to folder containing javascript files
#benign_target_folder_path = ".\\benign_subset_10pct"
#malicious_target_folder_path = ".\\malicious_subset_10pct"
benign_target_folder_path = ".\\benign"
malicious_target_folder_path = ".\\malicious"

#Set to 1 for paralell processing
#Increases speed of processing the dataset but runs risk of resource lock causing a program stall
parallel_processing = 0

# Output CSV location
output_file_loc = ".\\js_feature_extraction_all.csv"

# Prepare the first line of the output
#to add a new field: add here, add calculation in process(), 
fields = [
	'charLen',
	'avgChar',
	'numLines',
	'numStrings',
	'numUnicode',
	'numHexOct',
	'pcHuman',
	'pcWhitespace',
	'numMethods',
	'avgString',
	'avgArglen',
	'numComments',
	'avgCPL',
	'numWords',
	'pcWNC', 
	'entropy',
	'e_pct', 
	'n_pct', 
	't_pct', 
	'i_pct', 
	'o_pct', 
	'a_pct',
	'malicious']

#fields = ['entropy', 'e_pct', 'n_pct', 't_pct', 'i_pct', 'o_pct', 'a_pct', 'malicious']

with open(output_file_loc, 'w+', newline='') as outfile:
	write = csv.writer(outfile)
	write.writerow(fields)
	outfile.close()

def calculate_entropy(string):
	ent = 0.0
	'''print(len(string))
	print(string[0])
	print(type(string))
	print(type(string[0]))'''
	if len(string) < 2:
		return ent
	size = float(len(string))
	for b in range(128):
		freq = string.count(chr(b))
		if freq > 0:
			freq = float(freq) / size
			ent = ent + freq * math.log(freq, 2)
	return -ent

def process(input_file):
	# --------------------------------------------------------- #
	#					   CHARACTERS						  #
	# --------------------------------------------------------- #
	# Read the file in characters to get char specific features
	#print(input_file)
	file = open(input_file, encoding="ISO-8859-1").read()
	file_as_string = "".join(file)
	
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
	if num_strings > 0:	 # Catch divide by zero
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
	if len_chars > 0:	   # Catch divide by zero
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
	#						   WORDS						   #
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
	#						  LINES							#
	# --------------------------------------------------------- #
	# Read the file in lines to get the line specific features
	#file = open(os.path.join(target_folder_path, input_file), encoding="ISO-8859-1").readlines()
	file = open(os.path.join("", input_file), encoding="ISO-8859-1").readlines()

	# 03: Number of lines (num_lines)
	num_lines = len(file)

	# 02: Average characters per line (avg_char_line) & 13: Avg. comments per line (comments_per_line)
	avg_char_line = 0
	comments_per_line = 0
	if num_lines > 0:	   # Catch divide by zero
		avg_char_line = round(len_chars / num_lines,4)
		comments_per_line = round(num_comments / num_lines, 4)

	# 9: Number of methods called (num_methods) & 11: Avg. argument length (avg_arglen)
	avg_arglen = 0
	method_regex = r"[0-9a-zA-Z]{1,}?\(.*?\)"
	arg_regex = r"\((.*?)\)"
	methods = []
	for line in file:
		if '(' in line and ')' in line:
			if len(line) > 20000:	   # Need to put a limit on lines for this regex. Even using non-greedy regex this causes
				continue				# catastophic backtrace in long strings. If a line is >20k, its obfuscation anyway.
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
	
	# entropy
	entropy = calculate_entropy(file_as_string)
	
	#Number of functions
	
		
	
	#Average length of functions
	
	#Letter frequency (%) for e,n,t,i,o,a
	#Will count frequency of all ascii char
	char_frequency = {}
	file_char_count = 0
	for i in range(256):
		char_frequency[i] = 0
	
	for file_char in file_as_string:
		char_frequency[ord(file_char)] += 1
		file_char_count += 1
	#ignoring upper case for now
	if file_char_count > 0:
		e_pct = char_frequency[101]/file_char_count
		n_pct = char_frequency[110]/file_char_count
		t_pct = char_frequency[116]/file_char_count
		i_pct = char_frequency[105]/file_char_count
		o_pct = char_frequency[111]/file_char_count
		a_pct = char_frequency[97]/file_char_count
	else:
		e_pct = 0
		n_pct = 0
		t_pct = 0
		i_pct = 0
		o_pct = 0
		a_pct = 0
		

	# --------------------------------------------------------- #
	#						 OUTPUT							#
	# --------------------------------------------------------- #
	outlist = [
		len_chars, 
		avg_char_line, 
		num_lines, 
		num_strings, 
		num_unicode, 
		hex_or_oct_chars, 
		pc_human, 
		whitespace_pc, 
		num_methods, 
		avg_strlen, 
		avg_arglen, 
		num_comments, 
		comments_per_line, 
		num_words, 
		words_not_comments,
		entropy, 
		e_pct, 
		n_pct, 
		t_pct, 
		i_pct, 
		o_pct, 
		a_pct,
		malicious]
	#outlist = [entropy, e_pct, n_pct, t_pct, i_pct, o_pct, a_pct, malicious]

	outfile = open(output_file_loc, 'a', newline='')
	write = csv.writer(outfile)
	write.writerow(outlist)
	outfile.close()

	return outlist

def get_js_files(file_paths):
	filelist = []
	filepaths = file_paths
	i = 0
	while i < len(filepaths):
		try:
			for item in os.listdir(filepaths[i]):
				item_full_path = os.path.join(filepaths[i], item)
				if os.path.isfile(item_full_path) and item_full_path[-3:] == '.js':
					#found .js file
					filelist.append(item_full_path)
				elif os.path.isdir(item_full_path):
					#found dir
					filepaths.append(item_full_path)
		except FileNotFoundError:
			print("File error, skipping")
		i += 1
	return filelist
		    

#given a list of file paths, recursively search for all js files in those file paths
#assumption that file path given only contains folders and .js files, otherwise will break
'''def get_js_files(file_paths):
	filelist = []
	
	#final case where all paths searched
	if len(file_paths) == 0:
		return []

	for item in os.listdir(file_paths[0]):
		item_full_path = os.path.join(file_paths[0] ,item)
		print(item_full_path)
		#if is .js file then add path to filelist
		if os.path.isfile(item_full_path) and item[-3:] == '.js':
			filelist.append(item_full_path)
		elif os.path.isdir(item_full_path):
			file_paths.append(item_full_path)
		#if is folder then append to file_paths
	#
	if len(file_paths) == 1:
		return filelist
	else:
		return filelist + get_js_files(file_paths[1:])'''

# Process metrics
start_time = time.time()

# Are these benign files or malicious files (0 = benign, 1 = malicious)
malicious = "Benign"

#iterate filesystem for benign js files
benign_js_file_list = get_js_files([benign_target_folder_path])
print("File system iterated, " + str(len(benign_js_file_list)) + " .js files found in benign dataset")

# Create the iterable for thread pool
print("Commencing processing benign scripts...")

main_output_list = []

files_complete = 0
pct_complete = 0

#updates the percentage complete, prints result if a whole percent is incremented
def update_pct_complete(files_complete, files_total, pct_complete, data_set_name):
	if pct_complete < round(files_complete/files_total, 0):
		print(str(pct_complete + 1) + "% complete processing " + data_set_name + " scripts")
	return round(files_complete/files_total, 0)

if parallel_processing:
	with concurrent.futures.ThreadPoolExecutor() as executor:
		futures = []
		for infile in benign_js_file_list:
			futures.append(executor.submit(process, input_file=infile))
			files_complete += 1
			#print(files_complete)
			#pct_complete = update_pct_complete(files_complete, len(benign_js_file_list), pct_complete, "benign")
		for future in concurrent.futures.as_completed(futures):
			main_output_list.append(future.result())
			executor.shutdown()
else:
	for infile in benign_js_file_list:
		process(infile)
		files_complete += 1
		#print(files_complete)
		#pct_complete = update_pct_complete(files_complete, len(benign_js_file_list), pct_complete, "benign")
		#if pct_complete < round(files_complete/len(benign_js_file_list)*100,0):
		#	pct_complete = round(files_complete/len(benign_js_file_list)*100,0)
		#	print(str(pct_complete) + "% complete processing benign scripts")
	

# Are these benign files or malicious files (0 = benign, 1 = malicious)
malicious = "Malware"

#iterate filesystem for malicious js files
malicious_js_file_list = get_js_files([malicious_target_folder_path])
print("File system iterated, " + str(len(malicious_js_file_list)) + " .js files found in malicious dataset")

# Create the iterable for thread pool
print("Commencing processing malicious scripts...")

main_output_list = []

files_complete = 0
pct_complete = 0

if parallel_processing:
	with concurrent.futures.ThreadPoolExecutor() as executor:
		futures = []
		for infile in malicious_js_file_list:
			futures.append(executor.submit(process, input_file=infile))
			files_complete += 1
			#print(files_complete)
			#pct_complete = update_pct_complete(files_complete, len(malicious_js_file_list), pct_complete, "malicious")
		for future in concurrent.futures.as_completed(futures):
			main_output_list.append(future.result())
			executor.shutdown()
else:
	for infile in malicious_js_file_list:
		process(infile)
		files_complete += 1
		#print(files_complete)
		#pct_complete = update_pct_complete(files_complete, len(malicious_js_file_list), pct_complete, "malicious")
		#if pct_complete < round(files_complete/len(malicious_js_file_list)*100,0):
		#	pct_complete = round(files_complete/len(malicious_js_file_list)*100,0)
		#	print(str(pct_complete) + "% complete processing malicious scripts")

print("Processing complete. Time taken:", round(time.time() - start_time,2), 'seconds')
print("Complete.")
