from termcolor import colored

def fuck():
    print '''
         __                        
        |  |                      
        |  |                        
       _|  |__ _                
  _  /  |  |  |  \                  
 |  |             |                 
  \ |             |
   \ _ _ _ _ _ _ /
'''

testing_functions = []

import test_upload
testing_functions.append({
    'function': test_upload.run,
    'title': 'testing upload'
})

import test_missings
testing_functions.append({
    'function': test_missings.run,
    'title': 'testing missings'
})

import test_delete
testing_functions.append({
    'function': test_delete.run,
    'title': 'testing delete'
})

import test_roles
testing_functions.append({
    'function': test_roles.run,
    'title': 'testing roles'
})

BASE_URL = 'http://188.166.62.205:8000/'
# BASE_URL = 'http://192.168.99.100:8000/'

results = []
for testing in testing_functions:
    func = testing['function']
    title = testing['title']
    this_result = func(BASE_URL)
    results.append(this_result)

print '\n\n--------'
are_all_tests = True
for i in range(len(results)):
    title = testing_functions[i]['title']
    result = results[i]
    if result:
        print colored('>> test %s successully complated' % title, 'green')
    else:
        print colored('>> test %s fuck' % title, 'red')
fuck()
print '--------'
