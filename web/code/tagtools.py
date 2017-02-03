import re


def strtolist(tagstring):
    string = re.sub('[ ,\n]+', ' ', tagstring).strip()
    array = string.split(' ')
    array = [x for x in array if x!='']
    return array