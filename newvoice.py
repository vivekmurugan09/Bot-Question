import speech_recognition as sr

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

a = ["what", "how", "why","is","in","your"]


# Split the input string into individual words
b = text.split()
print(b)

# Create a new list without the words to remove
filter = [word for word in b if word.lower() not in a]
print("filtered words=",filter)
# Join the filtered words back together
result = " ".join(filter)

print("Filtered sentence:=", result)