import speech_recognition as sr
import pandas as pd

# Initialize the recognizer
recognizer = sr.Recognizer()

# Use the microphone as the audio source
with sr.Microphone() as source:
    print("Adjusting for background noise... Please wait.")
    recognizer.adjust_for_ambient_noise(source, duration=2)
    print("Listening... Speak something!")
    audio = recognizer.listen(source)

# Convert speech to text using Google Speech Recognition

print("Recognizing...")
text = recognizer.recognize_google(audio)
print("You said:", text)

def A():
    with open("file1.txt", "r") as x:
        a = x.read()
        print(a)
        return(a)
a = ["what", "how", "why","is","in","your"]
b = text.split()
print(b) 

filter = [word for word in b if word.lower() not in a]
print("filtered words=",filter)
# Join the filtered words back together
result = " ".join(filter)

if result =='electric' or result == 'electro':
    a=A()
else:
    user_input = result
    
    user_input1 = "electromaganisum"