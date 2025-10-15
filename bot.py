import pandas as pd#GA with fuzzy
from fuzzywuzzy import fuzz
from fuzzywuzzy import process
import re
import pandas as pd
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import speech_recognition as sr

def A():
    with open("file1.txt", "r") as x:
        a = x.read()
        print(a)
        return(a)
def B():
    with open("file2.txt", "r") as x:
        b = x.read()
        print(b)
        return(b)
def C():
    with open("file3.txt", "r") as x:
        c = x.read()
        print(c)
        return(c)
def D():
    with open("file4.txt", "r") as x:
        d = x.read()
        print(d)
        return(d)
def E():
    with open("file5.txt", "r") as x:
        e = x.read()
        print(e)
        return(e)
def F():
    with open("file6.txt", "r") as x:
        f = x.read()
        print(f)
        return(f)
def G():
    with open("file7.txt", "r") as x:
        g = x.read()
        print(g)
        return(g)
def H():
    with open("file8.txt", "r") as x:
        h = x.read()
        print(h)
        return(h)
def I():
    with open("file9.txt", "r") as x:
        i = x.read()
        print(i)
        return(i)
def J():
    with open("file10.txt", "r") as x:
        j = x.read()
        print(j)
        return(j)

nltk.download('stopwords')
nltk.download('punkt')
recognizer = sr.Recognizer()
with sr.Microphone() as source:
    print("Adjusting for background noise... Please wait.")
    recognizer.adjust_for_ambient_noise(source, duration=2)
    print("Listening... Speak something!")
    audio = recognizer.listen(source)


print("Recognizing...")
text = recognizer.recognize_google(audio)
print("You said:", text)

#user_input = input("How can I help you? ")

tokens = word_tokenize(text)
stop_words = set(stopwords.words('english'))
words = text.lower()
filtered_words = [word for word in tokens if word.lower() not in stop_words]
key = " ".join(filtered_words)

if key =='electromag' or key == 'maganisum':
    a=A()
elif key == 'electric charge' or key == 'charge':
    b=B()
elif key == 'electric field' or key == 'field':
    c=C()
elif key == 'magnetic' or key == 'Magnetic field':
    d=D()
elif key == 'electromagnetic' or key == 'Electromag' or key == 'Induction':
    e=E()
elif key == 'AC' or key == 'DC' or key == 'AC Current' or key == 'DC Current':
    f=F()
elif key == 'Electromagnetic' or key == 'Spectrum' or key == 'electromagbetic':
    g=G()
elif key == 'electric' or key == 'magnetic field':
    h=H()
elif key == 'maxwells' or key == 'maxwells equation':
    i=I()
elif key == 'application' or key == 'electro':
    j=J()
else:
    user_input = key

    user_input1 = "electromaganisum"
    user_input2 = "electic charge"
    user_input3 = "electic field"
    user_input4 = "magnetic field"
    user_input5 = "electromagnetic induction"
    user_input6 = "AC DC current"
    user_input7 = "electromagbetic Spectrum"
    user_input8 = "electric magnetic field"
    user_input9 = "maxwells equation"
    user_input10 = "application electro"

    Y1=fuzz.WRatio(user_input, user_input1)
    print("electromaganisum =",Y1)
    Y2=fuzz.WRatio(user_input, user_input2)
    print("electric charge =",Y2)
    Y3=fuzz.WRatio(user_input, user_input3)
    print("electic field =",Y3)
    Y4=fuzz.WRatio(user_input, user_input4)
    print("magnetic =",Y4)
    Y5=fuzz.WRatio(user_input, user_input5)
    print("electromagnetic induction =",Y5)
    Y6=fuzz.WRatio(user_input, user_input6)
    print("current =",Y6)
    Y7=fuzz.WRatio(user_input, user_input7)
    print("Spectrum =",Y7)
    Y8=fuzz.WRatio(user_input, user_input8)
    print("electric magnetic field =",Y8)
    Y9=fuzz.WRatio(user_input, user_input9)
    print("maxwells equation =",Y9)
    Y10=fuzz.WRatio(user_input, user_input10)
    print("application electro =",Y10)

    if Y1 > 80 :
      M = A()
    elif Y2 > 80 :
      Z= B()
    elif Y3 > 80 :
      Y = C()
    elif Y4 > 80 :
      X = D()
    elif Y5 > 80 :
      W = E()
    elif Y6 > 80 :
      V = F()
    elif Y7 > 80 :
      T = G()
    else:
      print("Invalid input")