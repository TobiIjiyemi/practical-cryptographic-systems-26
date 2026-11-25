#!/usr/bin/env python3
"""Your implementation goes here (or delete this and use another language).
Subcommands the wrappers call: encrypt KEY FILE | decrypt KEY FILE |
keylength FILE | cryptanalyze FILE K"""
import sys
import heapq
import numpy as np
import random
import re

LETTER_TO_NUM = {}
ENGLISH_FREQ = {'A': 0.082, 'B': 0.014, 'C': 0.028, 'D': 0.038, 'E': 0.131, 'F': 0.029, 'G': 0.020, 'H': 0.053, 'I': 0.064, 'J': 0.001, 'K': 0.004, 'L': 0.034, 'M': 0.025, 'N': 0.071, 'O': 0.080, 'P': 0.020, 'Q': 0.001, 'R': 0.068, 'S': 0.061, 'T': 0.105, 'U': 0.025, 'V': 0.009, 'W': 0.015, 'X': 0.002, 'Y': 0.020, 'Z': 0.001}

def extract_text_from_file(file):
    regex = re.compile('[^a-zA-Z]')
    content = ""
    with open(file, "r") as target:
        content = target.read()
        content = "".join(  "".join(content.splitlines()).split(" ") ).upper()
        content = regex.sub('', content)
        return content
    return

def encrypt(key, text):
    i,j = 0,0
    cipher = ""
    while i < len(text):
        res = ord(text[i]) + LETTER_TO_NUM[key[j]]
        if res > ord('Z'):
            res = res % 91 + 65
        cipher += chr(res)
        j += 1
        j = j % len(key)
        i+=1
    return cipher
    

def decrypt(key, text):
    i, j = 0, 0
    plaintext = ""
    while i < len(text):
        res = ord(text[i]) - LETTER_TO_NUM[key[j]]
        if res < ord('A'):
            res = (res - ord('A')) + 91
        plaintext += chr(res)
        j += 1
        j = j % len(key)
        i+=1
    return plaintext

def IC_calculator(coset):
    counts = {}
    for i in coset:
        if i in counts:
            counts[i] += 1
        else:
            counts[i] = 1
    total = 0
    for key in counts.keys():
        freq = counts[key]
        total += (freq * (freq - 1))
    
    return (total/ ( len(coset) * (len(coset) - 1)   ))

def shift_coset(text, num):
    shift_result = ""
    for i in range(len(text)):
        res = ord(text[i]) - num
        if res < ord('A'):
            res = (res - ord('A')) + 91
        shift_result += chr(res)
    return shift_result

def calculate_goodness(text):
    total_count = len(text)
    counts = {}
    for i in text:
        if i in counts:
            counts[i] += 1
        else:
            counts[i] = 1
    #set the other letters that didn't show up to 0 
    for i in ENGLISH_FREQ.keys():
        if i not in counts:
            counts[i] = 0
    goodness = 0
    for letter in counts.keys():
        freq_in_text = counts[letter]/total_count
        freq_in_english = ENGLISH_FREQ[letter]
        goodness += (pow((freq_in_text - freq_in_english), 2)/freq_in_english)
    return goodness
    

def keylength(text):
    max_length = 32
    IC_collection = []
    for i in range(1, max_length+1):
        cosets = ["" for k in range(i)]
        for j in range(len(text)):
            cosets[j%i] += text[j]
        total = 0
        for cor in cosets:
            total += IC_calculator(cor)
        IC = total/(len(cosets))
        IC_collection.append(IC)
    max_ind = 0
    for ic in range(1, len(IC_collection)):
        if IC_collection[ic] > IC_collection[max_ind]:
            # design decision for ruling out repeated keys
            if (ic+1)%(max_ind+1) == 0 and (IC_collection[ic] - IC_collection[max_ind] > 0.005):
                max_ind = ic
            elif (ic+1)%(max_ind+1) != 0:
                max_ind = ic
    return max_ind + 1

def cryptanalyze(text, keyl):
    cosets = ["" for k in range(keyl)]

    for i in range(len(text)):
        cosets[i%keyl] += text[i]
    goodness_values = [[0 for j in range(26)] for i in range(keyl)]

    for i in range(len(cosets)):
        for letter in range(26):
            shifted = shift_coset(cosets[i], letter)
            goodness_values[i][letter] = calculate_goodness(shifted)

    shifts = [0 for i in range(keyl)]
    for c in range(len(cosets)):
        shifts[c] = goodness_values[c].index(min(goodness_values[c]))
    key = ""
    for s in shifts:
        key += chr(ord('A') + s)
    return key

def generate_key(length):
    key = ""
    for i in range(length):
        key += chr(ord('A') + random.randint(0, 25)) 
    return key

#Designing an experiment all by myself, I'm so excited!! nevermind that it's 2 days late :(

#receiving all the text in the file
def experiment(text):
    KEY_LENGTHS = [3,5,7,10,15,20]
    CIPHER_LENGTHS = [100, 200, 500, 1000, 2000, 5000, 20000]
    TRIALS = 25
    # results stored in a 2d array, cipher_lengths by key_lengths. each cell contains a tuple.
    # first element of tuple is the fraction of trials that my program correctly guessed the key length
    # second element is the fraction of trials in which the exact key was recovered
    RESULTS = [[(0, 0) for k in range(len(KEY_LENGTHS))] for c in range(len(CIPHER_LENGTHS))]
    
    for i in range(len(KEY_LENGTHS)):
        k_length = KEY_LENGTHS[i]
        for j in range(len(CIPHER_LENGTHS)):
            c_length = CIPHER_LENGTHS[j]
            key_length_success = 0
            key_success = 0
            for trial in range(TRIALS):
                #choose random part of the plaintext to experiment on
                index = random.randint(0, len(text)-(1+c_length))
                plaintext_to_encrypt = text[index:index+c_length]

                #generate random key
                random_k = generate_key(k_length)

                #encrypt plaintext with produced key
                target_encipherment = encrypt(random_k, plaintext_to_encrypt)

                #have program guess keylength
                guess_length = keylength(target_encipherment)
                if guess_length == k_length:
                    key_length_success += 1
                #have program guess the key
                guess_key = cryptanalyze(target_encipherment, guess_length)
                if guess_key == random_k:
                    key_success += 1
            first = key_length_success/TRIALS
            second = key_success/TRIALS
            RESULTS[j][i] = (first, second)
    print(RESULTS)
    return


def main():
    for i in range(ord('A'), ord('A')+26):
        LETTER_TO_NUM[chr(i)] = i - ord('A')
    programToRun = sys.argv[1]
    if programToRun == "encrypt":
        if len(sys.argv) == 4:
            key = sys.argv[2]
            file = sys.argv[3]
            text = extract_text_from_file(file)
            output = encrypt(key, text)
            print(output)
            return
        else:
            sys.exit("Argument Missing: key and file are required")
    elif programToRun == "decrypt":
        if len(sys.argv) == 4:
            key = sys.argv[2]
            file = sys.argv[3]
            text = extract_text_from_file(file)
            output = decrypt(key, text)
            print(output)
            return output
        else:
            sys.exit("Argument Missing: key and file are required")
    elif programToRun == "keylength":
        if len(sys.argv) == 3:
            file = sys.argv[2]
            text = extract_text_from_file(file)
            output = keylength(text)
            print(output)
            return
        else:
            sys.exit("Argument Missing: file is required")
    elif programToRun == "cryptanalyze":
        if len(sys.argv) == 4:
            file = sys.argv[2]
            keyl = int(sys.argv[3])
            text = extract_text_from_file(file)
            output = cryptanalyze(text, keyl)
            print(output)
            return
        else:
            sys.exit("Argument Missing: file and keylength are required")
    elif programToRun == "experiment":
        if len(sys.argv) == 3:
            file = sys.argv[2]
            text = extract_text_from_file(file)
            experiment(text)
            return
        else:
            sys.exit("Argument missing: file is required")
    else:
        sys.exit("Don't recognize that argument sorry")
if __name__ == "__main__":
   main()