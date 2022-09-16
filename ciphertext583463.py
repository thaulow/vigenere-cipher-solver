#!/usr/bin/env python
# -*- coding: utf-8 -*-
__AUTHOR__ = "Thomas Thaulow Stöcklin (583463)"
__EMAIL__ = "thomasts@stud.ntnu.no"

from decimal import *

######################### CHANGEABLE VARIABLES #########################
FILE_NAME = "ciphertext583463.txt"  # filename to process
MAX_ATTEMPTS = 50                   # guess key-length up to xx attempts
######################### CHANGEABLE VARIABLES #########################
LETTERS = []                        #
for let in range(65, 91):          #  define the alphabet a-z
    LETTERS.append(chr(let))        #

STUDENT_ID = ''.join([i for i in FILE_NAME if i.isdigit()])

english_frequency = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,   #
					   0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, # a-z letter frequency table found here: https://www3.nd.edu/~busiforc/handouts/cryptography/Letter%20Frequencies.html
					   0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, #
					   0.00978, 0.02360, 0.00150, 0.01974, 0.00074]
english_frequency = [Decimal(i) for i in english_frequency]                           # convert frequency table from float to decimal to mitigate precision issues.

# Parse file to suitable format and add to list
def parse_file(FILE_NAME):                                                                          # define function
    with open(FILE_NAME, "r") as file:                                                              # open file as read, and proceed with file
        CIPHERTEXT =  ''.join(file.readlines()).upper().replace(" ", "")                            # add file contents, remove spacing, lowercase 
        file.close()                                                                                # close file
        return ''.join([secret_letter for secret_letter in CIPHERTEXT if secret_letter in LETTERS]) # return only valid letters from letters attribute
        
def write_to_file(filename,attribute):                                # define function
            file = open(filename, "w")                                # open file in write format, overwriting any previous content
            file.write(f"{attribute}")                                # write attribute contents to file 
            file.close()                                              # close file

# Find Key Length
def find_key_length():                                          # define function
    winning_iteration = (0, 0)                                  # initiate empty tuple for counting outside of loop
    for i in range(1, MAX_ATTEMPTS+1):                          # iterate key-length 0 to defined max value from MAX_ATTEMPTS variable 
        temp_array=set()                                        # initiate set for collecting probability sum outside of loop
        for x in range(1, i+1):                                 # iterate 
            letter_freq = count_letters(CIPHERTEXT[x::i])       # add return value from count_letters (count of letters in cipher) to letter_freq
            IoC = compute_ioc(letter_freq)                      # add return value from compute_ioc (probability value of each letter) to IoC. 
            temp_array.add(IoC)                                 # add IoC (probability value of letters) to temp_array outside loop
        keylength = sum(temp_array)/len(temp_array)             # add total sum of temp_array (IoC) attribute and divide it by the length of the temp_array
        iteration, max_keylength = winning_iteration            # add iteration number (key length) and maximum keylength found into winning_iteration attribuet
        if keylength > max_keylength:                           # if a keylength is greater then max_keylength, then proceed to next line
            winning_iteration = i, keylength                    # add the number of iteration (key length), and the keylength attribute to winning_iteration
    print("Compared probability in steps from", 1, "to", MAX_ATTEMPTS)      #print what range of keywords was attempted, as specified in global variable line 10
    print("Key-length:",winning_iteration[0])                               # print the first column in winning_iteration, showing iteration number (key length)
    return winning_iteration[0]                                             # return first column in winning_iteration, for iteration number (key length)

# Count occurence of letters
def count_letters(CIPHERTEXT):              # define function
    letter_freq = []                        # initiate empty list, used to collect letter counts outside the loop
    for letter in range(len(LETTERS)):      # iterate every letter in alphabet
        counter = 0                         # initiate empty integer, used for counting
        for char in CIPHERTEXT:             # iterate ciphertext
            if char == LETTERS[letter]:     # if n in ciphertext == n in alphabet
                counter += 1                # add 1 to count
        letter_freq.append(counter)         # at end of count, append count to variable letter_freq
    return letter_freq                      # return variable letter_freq with list of count per letter in alphabet

# Compute Index of Coincidence
def compute_ioc(letter_freq):                                               # define function
    IoC = 0                                                                 # Initiate empty integer, to collect letter counts outside the loop
    for letter_sum in range(len(letter_freq)):                              # Iterate through alphabet count 
        IoC += letter_freq[letter_sum] * (letter_freq[letter_sum] - 1)      # Sum probability of same letter twice. A * (A-1) 
    IoC = IoC / (sum(letter_freq) * (sum(letter_freq) - 1))                 # Same letter twice divided by cipher length twice. (A*(A-1))/C * (C-1).               
    return IoC                                                              # Return probability of letter occuring as variable IoC. 

# Find frequency analysis
def freq_analysis(keylength):               # define function
    keyword = []                            # Initiate variable for saving shift outside loop per group, resulting in the keyword
    for group in range(keylength):          # ITERATE FOR EACH CHARACTER IN THE KEYWORD, GROUPED BY KNOWN KEY LENGTH. 
        winning_iteration = (1,1)           # Initiate winning variable in shift loop, giving the closest match between english alphabet and the cipher.  
        for shift in range(len(LETTERS)):   # ITERATE AMOUNT OF SHIFTS FOR LETTERS, TO COMPAER AGAINST THE ENGLISH LETTER. 
            freq_sum = []                # Initiate variable for collecting sum of probability_frequency - english_frequency to find most similar match
            letter_frequency = count_letters(CIPHERTEXT[group::keylength])  # Group Ciphertext into groups equal to keylength and count them. Add to letter_frequecy
            letter_frequency = letter_frequency[shift:]+letter_frequency[:shift]      # Take value from letter_frequency and shift based on shift loop iteration
            for letter in range(len(LETTERS)):                                          # ITERATE FOR EVERY LETTER IN THE ALPHABET 
                probability_AA = letter_frequency[letter]*(letter_frequency[letter]-1)  # Calculate probability of 2 letters after each other (A * A)
                probability_frequency = Decimal(probability_AA / (sum(letter_frequency) * (sum(letter_frequency)-1)))   # Calculate probability of AA in ciphertext 
                freq_sum.append(abs(probability_frequency - english_frequency[letter])) # take probability of two letters minus expected probability and add to freq_sum attribute
                winning = sum(freq_sum)                                                 # add sum of freq_sum to winning attribute
            iteration, max_keylength = winning_iteration                                # add iteration count and max keylength to winning_iteration
            if winning < max_keylength:                                                 # if current winning value is lower then max_keylength
                winning_iteration = shift, winning                                      # add iteration count and value to winning_iteration
        keyword.append(LETTERS[winning_iteration[0]])                                   # add the letter equalient of iteration to keyword attribute
    keyword = "".join(keyword)                                                          # convert keyword from list to string
    return(keyword)                                                                     # return keyword as string form.        

def originalText(CIPHERTEXT, keyword):                                                                  # define function
    plaintext = []                                                                                      # initiate empty list
    keyword_iteration = 0                                                                               # initiate empty integer 
    for iteration in range(len(CIPHERTEXT)):                                                            # iterate through every character in ciphertext
        plaintext.append(chr((ord(CIPHERTEXT[iteration]) - ord(keyword[keyword_iteration])) %26 +65))   # add ciphertext character with letter shift to plaintext attribute.
        if keyword_iteration != (len(keyword)-1):                                                       # if loop has not counted 7 times
            keyword_iteration += 1                                                                      # add +1 count to loop. Continue 
        elif keyword_iteration == (len(keyword)-1):                                                     # if loop has gone 7 times
            keyword_iteration = 0                                                                       # reset attribute value to 0. Continue
    plaintext = "".join(plaintext)                                                                      # convert plaintext from list to string
    return(plaintext)                                                                                   # return value plaintext as string.

######################### START OF APPLICATION ###########################
if __name__ == '__main__':                                      #initiate file
    print("Starting Vigenère Cipher: Frequency Analysis")       # print information text
    CIPHERTEXT = parse_file(FILE_NAME)                          # add contents from file specified in global variable line 9, to attribute CIPHERTEXT
    print(FILE_NAME," parsed successfully")                     # print information text confirming file-name
    keylength = find_key_length()                               # initiate function find_key_length and add return values to attribute keylength
    keyword = freq_analysis(keylength)                          # initiate function freq_analysis with value from keyword function, line 112. Add output to keyword
    write_to_file("key"+STUDENT_ID+".txt",keyword)             # initiate write to file function and pass filename and attribute keyword for processing. 
    print("The keyword is: ", keyword)                          # print keyword attribute value
    plaintext = originalText(CIPHERTEXT, keyword)               # initiate OriginalText function, pass ciphertext and keyword, add output to plaintext attribute. 
    write_to_file("plaintext"+STUDENT_ID+".txt",plaintext)         # initiate write to file function and pass filename and attribute plaintext for processing.
    print("The Decrypted message is:", plaintext)               # print plaintext attribute value
######################### END OF APPLICATION ############################