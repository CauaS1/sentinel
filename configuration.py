import json

def load_configuration():
    with open("configuration.json", "r") as file:
        return json.load(file)

jsonConfig = load_configuration()

print(jsonConfig["database"]["interface"])