#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def read_letter(sentence,num):
    sentence = str(sentence.replace(" ",""))
    return sentence[num]

while True:
    a= str(raw_input("Type Sentence: "))
    b = int(raw_input("Type Num: "))
    print(read_letter(a,b+1))