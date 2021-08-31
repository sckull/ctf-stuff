#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#lenguaje => https://morsecode.scphillips.com/morse.html
lenguaje = {'di-dah':'A','dah-di-di-dit':'B','dah-di-dah-dit':'C','dah-di-dit':'D','dit':'E','di-di-dah-dit':'F','dah-dah-dit':'G','di-di-di-dit':'H','di-dit':'I','di-dah-dah-dah':'J','dah-di-dah':'K','di-dah-di-dit':'L','dah-dah':'M','dah-dit':'N','dah-dah-dah':'O','di-dah-dah-dit':'P','dah-dah-di-dah':'Q','di-dah-dit':'R','di-di-dit':'S','dah':'T','di-di-dah':'U','di-di-di-dah':'V','di-dah-dah':'W','dah-di-di-dah':'X','dah-di-dah-dah':'','dah-dah-di-dit':'Z','dah-dah-dah-dah-dah':'0','di-dah-dah-dah-dah':'1','di-di-dah-dah-dah':'2','di-di-di-dah-dah':'3','di-di-di-di-dah':'4','di-di-di-di-dit':'5','dah-di-di-di-dit':'6','dah-dah-di-di-dit':'7','dah-dah-dah-di-dit':'8','dah-dah-dah-dah-dit':'9','di-dah-di-dah':'ä','di-dah-dah-di-dah':'á','di-dah-dah-di-dah':'å','dah-dah-dah-dah':'Ch','di-di-dah-di-dit':'é','dah-dah-di-dah-dah':'ñ','dah-dah-dah-dit':'ö','di-di-dah-dah':'ü','di-dah-di-di-dit':'&','di-dah-dah-dah-dah-dit':'\'','di-dah-dah-di-dah-dit':'@','dah-di-dah-dah-di-dah':')','dah-di-dah-dah-dit':'(','dah-dah-dah-di-di-dit':':','dah-dah-di-di-dah-dah':',','dah-di-di-di-dah':'=','dah-di-dah-di-dah-dah':'!','di-dah-di-dah-di-dah':'.','dah-di-di-di-di-dah':'-','di-dah-di-dah-dit':'+','di-di-dah-dah-di-dit':'?','dah-di-di-dah-dit':'/'}
pipi = "dah-dah-dah di-dah-dah di-dah di-di-dit di-dah-dah-dit dah-dah-dah-dah-dah di-dah-dah-dah-dah di-di-dah-dah-dah di-di-di-dah-dah di-di-di-di-dah di-di-di-di-dit dah-di-di-di-dit dah-dah-di-di-dit dah-dah-dah-di-dit dah-dah-dah-dah-dit"
print(pipi)
#tmp - morse words
morse = []
word_tmp = ''
translate = ''
#remove the espace from the string
morse = pipi.split()
#print(morse)

for k in range(0,len(morse)):
	if morse[k] in lenguaje:		
		translate+=lenguaje[morse[k]]
	else:
		pass

print(translate)