import csv
import sys
import re


# first argument the input file and second the codebook

if len(sys.argv) < 3:
    print("Usage: python3 auto_label.py <inputfile.csv> <codebook.csv>")
    sys.exit(1)


regex = re.compile('[^a-zA-Z]')
#First parameter is the replacement, second parameter is your input string
regex.sub('', 'ab3d*E')

csvfilename = 'top_2024_01_19.csv'
csvfilename = sys.argv[1]

#outputfilename = 'top_2024_01_19_labeled.csv'
outputfilename = csvfilename.replace(".csv", "_labeled.csv")

dictfilename = 'codes.csv'
dictfilename = sys.argv[2]

# filler words
fillers = "and in this a & we will be for on is would or of with to not the when if that |  ".split(" ")

# COLUMNS
app_id = 0
app_id_header = "app_id"
text_de = 1
text_de_header = "de"
text_en = 2
text_en_header = "en"
text_tr = 3
text_tr_header = "translate"
label = 4
label_header = "auto code"

keywords_global = {}

def readFiles():
    codes = dict()

    with open(dictfilename, newline='') as dictfile:
        dictreader = csv.reader(dictfile, delimiter=';', quotechar='|')
        for row in dictreader:
            codes.update({row[0]: row[1].split(",")})


    with open(csvfilename, newline='') as csvinfile, open(outputfilename, 'w+', newline='') as csvoutfile:
        csvreader = csv.reader(csvinfile, delimiter=';', quotechar='"')
        headerrow = next(csvreader, None)
        label_index = len(headerrow)
        headerrow.append(label_header)

        csvwriter = csv.writer(csvoutfile, delimiter=';', quotechar='"')
        csvwriter.writerow(headerrow)
        for row in csvreader:
            row = processRow(row, codes, label_index)
            csvwriter.writerow(row)

def processRow(row: list, codes: dict, label_index: int):
    
    if getText(row,text_en):
        full_text = getText(row,text_en)
    else:
        full_text = getText(row,text_tr)

    print(full_text)


    regex = re.compile('[^a-zA-Z\-\ \n]')
    #First parameter is the replacement, second parameter is your input string
    full_text = regex.sub('', full_text)
    # clean up text: remove newlines, double spaces, quotation marks
    full_text = " ".join(full_text.split()).lower()

    countKeywords(full_text)

    row_codes = []
    for code in codes:
        if any(keyword in full_text for keyword in codes[code]):
            row_codes.append(code)
    
    return extenedRow(row, label_index, (', ').join(row_codes))

def getText(row, index):
    try:
        return row[index]
    except IndexError:
        return ""

def extenedRow(row, index, value):
    pad = index - len(row)
    if pad > 0: row.append(['']*pad) 
    row.append(value)
    return row

def countKeywords(text):
    global keywords_global

    for word in text.split(" "):
        if not word in fillers:
            if word in keywords_global:
                keywords_global[word] = keywords_global[word] + 1
            else:
                keywords_global[word] = 1

def printKeywords(keywords):
    sortedKeywords = dict(sorted(keywords.items(), key=lambda item: item[1]))
    for k in sortedKeywords:
        if sortedKeywords[k] > 1:
            print(k + ": " + str(sortedKeywords[k]))


if __name__ == '__main__':
    readFiles()
    printKeywords(keywords_global)
