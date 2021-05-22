#!/usr/bin/python3

# Credits: Modified GitHub Dorker using GitAPI and my personal compiled list of dorks across multiple resources. API Integration code borrowed and modified from Gwendal Le Coguic's scripts.
# Author: Daniele Volpe



print("""




oooooooooooo                           oooooooooo.                      oooo
`888'     `8                           `888'   `Y8b                     `888
 888          .ooooo.  oooo    ooo      888      888  .ooooo.  oooo d8b  888  oooo   .ooooo.  oooo d8b
 888oooo8    d88' `88b  `88b..8P'       888      888 d88' `88b `888""8P  888 .8P'   d88' `88b `888""8P
 888    "    888   888    Y888'         888      888 888   888  888      888888.    888ooo888  888
 888         888   888  .o8"'88b        888     d88' 888   888  888      888 `88b.  888    .o  888
o888o        `Y8bod8P' o88'   888o     o888bood8P'   `Y8bod8P' d888b    o888o o888o `Y8bod8P' d888b




Find GitHub secrets utilizing a vast list of GitHub dorks and the GitHub search api. The
purpose of this tool is to enumerate interesting users,repos, and files to provide an
easy to read overview of where a potential sensitive information exposure may reside.

HELP: python3 FoxDorker.py -h
Example: python3 FoxDorker.py -tf tokens.txt -d ./Dorks/wordlist.txt -org singleDomain.txt -e 9
""")

# IMPORTS
import sys
import json
import time
import argparse
import random
import requests
import csv
import urllib.request
import re
import os
import threading
from itertools import zip_longest
from termcolor import colored
import multiprocessing
from multiprocessing.dummy import Pool, Lock
from collections import defaultdict
from urllib.error import HTTPError
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# API CONFIG
GITHUB_API_URL = 'https://api.github.com'

# PARSER CONFIG
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--dorks", help="dorks file (required)")
parser.add_argument("-k", "--keyword", help="search on a keyword instead of a list of dorks")
parser.add_argument("-q", "--query", help="query (required or -q)")
parser.add_argument("-u", "--users", help="users to perform dork or keyword search on (comma separated).")
parser.add_argument("-uf", "--userfile", help="file containing new line separated users")
parser.add_argument("-org", "--organization",
                    help="organization's GitHub name (required or -org if query not specified)")
parser.add_argument("-t", "--token", help="your github token (required if token file not specififed)")
parser.add_argument("-tf", "--tokenfile", help="file containing new line separated github tokens ")
parser.add_argument("-e", "--threads", help="maximum n threads, default 1")
parser.add_argument("-o", "--output", help="output to file name (required or -o)")
parser.parse_args()
args = parser.parse_args()

# DECLARE LISTS
tokens_list = []
dorks_list = []
queries_list = []
organizations_list = []
users_list = []
keywords_list = []
searchesDone=set()
# rows = []

# SET COUNT
count = 0
keyword_count = 0
globalResetTime=0

#New files
myfile= open("/home/kali/bin/FoxDorker/urls.txt","w+")
myfile.truncate(0)
myfile.close()
myfile1= open("/home/kali/bin/FoxDorker/FailedUrls.txt","w+")
myfile1.truncate(0)
myfile1.close()
querysearched= open("/home/kali/bin/FoxDorker/querysearched.txt","w+")
querysearched.truncate(0)
querysearched.close
savetext=open("/home/kali/bin/FoxDorker/files/try.txt","w+")
savetext.truncate(0)
savetext.close()

dictionary = defaultdict(list)           #create dictionary to store the results
regexes = []                             #list where are stored the regexes
with open("/home/kali/bin/FoxDorker/Dorks/regexes.txt","r") as f:
    for string in f:
        regexes.append(string.strip())
tokens_dictionary=defaultdict(int)




start= time.time()
finish= 0
matches=["filename","extension","language"]
lock = Lock()




# TOKEN ARGUMENT LOGIC
if args.token:
    tokens_list = args.token.split(',')

if args.tokenfile:
    tokens_list=[]
    with open("/home/kali/bin/FoxDorker/tokens.txt","r") as f2:
        for token in f2:
            tokens_list.append(token.strip())
            tokens_dictionary[token.strip()]=10


if not len(tokens_list):
    parser.error('auth token is missing')

# USER ARGUMENT LOGIC
if args.users:
    users_list = args.users.split(',')

if args.userfile:
    with open(args.userfile) as f:
        users_list = f.read().splitlines()

if args.query:
    queries_list = args.query.split(',')

if args.query and args.keyword:
    parser.error('you cannot specify both a query and a keyword, please specify one or the other.')

if args.query and args.organization:
    parser.error('you cannot specify both a query and a organization, please specify one or the other.')

if args.organization:
    #organizations_list = args.organization.split(',')
    with open(args.organization) as f:
       organizations_list = f.read().splitlines()

if args.threads:
    threads = int(args.threads)
else:
    threads = 1

if not args.query and not args.organization and not args.users and not args.userfile:
    parser.error('query or organization missing or users missing')

if args.dorks:
    fp = open(args.dorks, 'r')
    for line in fp:
        dorks_list.append(line.strip())

if args.keyword:
    keywords_list = args.keyword.split(',')

if not args.dorks and not args.keyword:
    parser.error('dorks file or keyword is missing')

# TOKEN ROUND ROBIN
n = -1

sys_random=random.SystemRandom()
def token_round_robin():
    global n
    with lock:
        t=0
        '''
        while (max(tokens_dictionary.items(), key=lambda x: x[1])[1])<2 :
            time.sleep(1)
            t=t+1
            if (t>60):
                return random.choice(list(tokens_dictionary))
            print(max(tokens_dictionary.items(), key=lambda x: x[1])[1])
        '''
        n=n+1
        if n >= len(tokens_list):
            n = 0
        current_token=max(tokens_dictionary, key=tokens_dictionary.get)
        tokens_dictionary[current_token]-=1
        #print(current_token + " has remainining " + str(tokens_dictionary[current_token]))

        return current_token
'''
def request(rateLimitRemaining):
     with lock:
         tokens_dictionary[current_token]=rateLimitRemaining
     return
'''


def black_token():
    #print(time.ctime())
    threading.Timer(60, foo).start()

# API SEARCH FUNCTION
def api_search(url):

    #global finish
    #global start
    global globalResetTime
    start=1
    finish=0
    #in [*range(len(tokens_list))]
    '''


    if ( ((stats_dict['n_current']) % ((len(tokens_list)-1)*10) ==0) and (stats_dict['n_current'] > 80)):
        start= time.time()
        finish=int(start) +60
        #print("rate limiting occured: sleep for 60 seconds...")
        time.sleep(60)
        #print("finished the nap")

    start= time.time()
    if (finish > start):
        wait= finish-int(start)
        #print("you have to wait! seconds to wait: " + str(wait))
        time.sleep(wait)
        #print("finished the nap")
    '''
    stats_dict['n_current'] = stats_dict['n_current'] + 1
    #print("n. query: " + str(stats_dict['n_current']) )
    try:
        current_token=token_round_robin()
        headers = {"Authorization": "token " + current_token}
        url+="&per_page=100&page=1"
        try:
            r = requests.get(url, headers=headers, timeout=10, verify=False)
        except requests.exceptions.RequestException as e:
            r = requests.get(url, headers=headers, timeout=10, verify=False)
            #print("request HTTP error captured!")
        rateLimitRemaining=int(r.headers.get('X-RateLimit-Remaining'))
        rateLimitReset=int(r.headers.get('X-RateLimit-Reset'))+5
        tokens_dictionary[current_token]=rateLimitRemaining
        if (rateLimitRemaining<=1):
            zzz=-1
            if current_token in tokens_list:
                tokens_list.remove(current_token)
            while(int(time.time())<=rateLimitReset):
                time.sleep(1)
                zzz+=1
                #if(zzz==0):
                    #print(current_token + " is gone to sleep")
                    #print(tokens_dictionary)
            tokens_dictionary[current_token]=10
            if current_token not in tokens_list:
                tokens_list.append(current_token)
        json = r.json()
        if 'documentation_url' in json:
            print(colored("[-] error occurred documentation_url: %s" % json['documentation_url'], 'red'))
            print("Exception: "+ url+ "\n")
            errors=["rate-limiting","abuse-rate-limits"]
            if any(x in json['documentation_url'] for x in errors):
                start= time.time()
                finish=int(start) +60
                #print("rate limiting occured: sleep for 60 seconds...")
                #print(current_token + " is gone to sleep(documentation url)")
                time.sleep(60)
                #print("finished the nap")
                current_token=token_round_robin()
                headers = {"Authorization": "token " + current_token}
                url+="&per_page=100&page=1"
                try:
                    r = requests.get(url, headers=headers, timeout=10, verify=False)
                except requests.exceptions.RequestException as e:
                    r = requests.get(url, headers=headers, timeout=10, verify=False)
                #print("request HTTP error captured!")
                rateLimitReset=int(r.headers.get('X-RateLimit-Reset'))+5
                rateLimitRemaining=int(r.headers.get('X-RateLimit-Remaining'))
                tokens_dictionary[current_token]=rateLimitRemaining
                json= r.json()
                if (rateLimitRemaining<=1):
                    zzz=-1
                    if current_token in tokens_list:
                        tokens_list.remove(current_token)
                    while(int(time.time())<=rateLimitReset):
                        time.sleep(1)
                        zzz+=1
                        #if(zzz==0):
                            #print(current_token + " is gone to sleep")
                            #print(tokens_dictionary)
                    tokens_dictionary[current_token]=10
                    if current_token not in tokens_list:
                        tokens_list.append(current_token)
            else:
                current_token=token_round_robin()
                headers = {"Authorization": "token " + current_token}
                url+="&per_page=100&page=1"
                try:
                    r = requests.get(url, headers=headers, timeout=10, verify=False)
                except requests.exceptions.RequestException as e:
                    r = requests.get(url, headers=headers, timeout=10, verify=False)
                #print("request HTTP error captured!")
                rateLimitReset=int(r.headers.get('X-RateLimit-Reset'))+5
                rateLimitRemaining=int(r.headers.get('X-RateLimit-Remaining'))
                tokens_dictionary[current_token]=rateLimitRemaining
                json= r.json()
                if (rateLimitRemaining<=1):
                    zzz=-1
                    if current_token in tokens_list:
                        tokens_list.remove(current_token)
                    while(int(time.time())<=rateLimitReset):
                        time.sleep(1)
                        zzz+=1
                        #if(zzz==0):
                            #print(current_token + " is gone to sleep")
                            #print(tokens_dictionary)
                    tokens_dictionary[current_token]=10
                    if current_token not in tokens_list:
                        tokens_list.append(current_token)



        if('total_count' in json):
            url_results_dict[url] = json['total_count']
            query0=url[url.find('+'):]          #query with +
            query=query0[1:]                    #search query
            if ((url_results_dict[url] > 0) and (len(query) < 128)):
                #print(len(searchesDone))
                while 'next' in r.links.keys():
                    #in [*range(len(tokens_list))]
                    '''
                    if ((stats_dict['n_current']) % ((len(tokens_list)-1)*10) ==0) and (stats_dict['n_current'] > 80):
                        start= time.time()
                        finish=int(start) +60
                        #print("internal rate limiting occured: sleep for 60 seconds...")
                        time.sleep(60)
                        #print("internal finished the nap")
                    start= time.time()
                    if (finish > start):
                        wait= finish-int(start)
                        #print("internal loop you have to wait! seconds to wait: " + str(wait))
                        time.sleep(wait)
                        #print("internal loop finished the nap")
                    '''
                    next_url=r.links['next']['url']
                    stats_dict['n_current'] = stats_dict['n_current'] + 1
                    #print("n. query next_query: " + str(stats_dict['n_current']) )
                    current_token=token_round_robin()
                    headers = {"Authorization": "token " + current_token}
                    try:
                        r = requests.get(next_url, headers=headers, timeout=10, verify=False)
                    except requests.exceptions.RequestException as e:
                        r = requests.get(url, headers=headers, timeout=10, verify=False)
                    #print("request HTTP error captured!")
                    rateLimitReset=int(r.headers.get('X-RateLimit-Reset'))+5
                    rateLimitRemaining=int(r.headers.get('X-RateLimit-Remaining'))
                    tokens_dictionary[current_token]=rateLimitRemaining
                    if (rateLimitRemaining<=1):
                        zzz=-1
                        if current_token in tokens_list:
                            tokens_list.remove(current_token)
                        while(int(time.time())<=rateLimitReset):
                            time.sleep(1)
                            zzz+=1
                            #if(zzz==0):
                                #print(current_token + " is gone to sleep")
                                #print(tokens_dictionary)
                        tokens_dictionary[current_token]=10
                        if current_token not in tokens_list:
                            tokens_list.append(current_token)
                    json2=r.json()
                    if 'documentation_url' in json2:
                        print(colored("[-] error occurred documentation_url: %s" % json2['documentation_url'], 'red'))
                        print("Exception: "+ next_url+ "\n")
                        errors=["rate-limiting","abuse-rate-limits"]
                        if any(x in json2['documentation_url'] for x in errors):
                            start= time.time()
                            finish=int(start) +60
                            #print("internal loop rate limiting occured: sleep for 60 seconds...")
                            #print(current_token + " is gone to sleep")
                            time.sleep(60)
                            #print("internal loop finished the nap")
                            current_token=token_round_robin()
                            headers = {"Authorization": "token " + current_token}

                            try:
                                r = requests.get(url, headers=headers, timeout=10, verify=False)
                            except requests.exceptions.RequestException as e:
                                r = requests.get(url, headers=headers, timeout=10, verify=False)
                            #print("request HTTP error captured!")
                            rateLimitReset=int(r.headers.get('X-RateLimit-Reset'))+5
                            rateLimitRemaining=int(r.headers.get('X-RateLimit-Remaining'))
                            tokens_dictionary[current_token]=rateLimitRemaining
                            if (rateLimitRemaining<=1):
                                zzz=-1
                                if current_token in tokens_list:
                                    tokens_list.remove(current_token)
                                while(int(time.time())<=rateLimitReset):
                                    time.sleep(1)
                                    zzz+=1
                                    #if(zzz==0):
                                        #print(current_token + " is gone to sleep")
                                tokens_dictionary[current_token]=10
                                if current_token not in tokens_list:
                                    tokens_list.append(current_token)
                            json2=r.json()
                            json['items'].extend(json2['items'])
                    else:
                        json['items'].extend(json2['items'])
                x=0
                y=1
                length=len(json["items"])
                for x in range(length):
                    #print(current_token)
                    s=json["items"][x]["html_url"]
                    block=["guide","doc","locale","auth","api","token","config","password","passwd","pwd","demo","secret","CHANGELOG","README",".md",".png","example","mock","test","sample","default","translation","translate","lang","Localiz","schema","template"]
                    if any( x.lower() in s.lower() for x in block):
                        continue
                    #print("SEARCH query: " + query + " count "+ str(x+1)+ " of TOTAL: " + str(url_results_dict[url]))
                    if (s in searchesDone):
                        #print("file already searched!")
                        continue
                    else:
                        searchesDone.add(s)
                    q=s.replace('/blob', '')
                    z=q.replace('github.com', 'raw.githubusercontent.com')
                    try:
                        response= requests.get(z, timeout=20, verify=False)
                        #response = urllib.request.urlopen(z)
                    except requests.exceptions.RequestException as e:
                        response= requests.get(z, timeout=20, verify=False)
                        #response = urllib.request.urlopen(z)
                        #print("HTTP error in z captured!!")
                    data = response.content
                    text = data.decode("utf-8","ignore")
                    line=0
                    while line<len(regexes):
                        match=[m.group().strip() for m in re.finditer(regexes[line], text, flags=re.IGNORECASE)]
                        line=line+1
                        n=0
                        if (len(match)>0):
                            #value=match.group(0)
                            if (n==0):
                                if s in dictionary:
                                    continue
                                print("\n")
                                print("URL: "+s)
                            for i in range(len(match)):
                                if (match[i] in dictionary[s]):
                                    continue
                                print("              " + match[i])
                                dictionary[s].append(match[i])
                            n=n+1
                            ips=[m.group().strip() for m in re.finditer("((?![a-z0-9]).|\s)((?!127\.0\.0\.1)[0-2]{0,1}[0-9]{1,2}\.[0-2]{0,1}[0-9]{1,2}\.[0-2]{0,1}[0-9]{1,2}\.[0-2]{0,1}[0-9]{1,2})((?![a-z0-9]).|\s)", text, flags=re.IGNORECASE)]
                            domains=[m.group().strip() for m in re.finditer("((?![A-Za-z0-9-\.]).)((?!example|foo)[A-Za-z0-9-\.]{1,120})(\.)(com|org|in|ir|au|uk|de|br|net|it|ru|us|co|icu|info|top|xyz|tk|gn|ga|cf|nl|fr|biz|online)((?![A-Za-z0-9-\.]).)", text, flags=re.IGNORECASE)]
                            for i in range(len(ips)):
                                if (ips[i] in dictionary[s]):
                                    continue
                                print("              " + ips[i])
                                dictionary[s].append(ips[i])
                            for j in range(len(domains)):
                                if (domains[j] in dictionary[s]):
                                    continue
                                print("              " + domains[j])
                                dictionary[s].append(domains[j])
                            #if("test" in s):
                            #    print("ATTENTION: probably is only for testing purpose")

                            '''
                            with open("/home/kali/bin/FoxDorker/urls.txt", "a") as myfile2: 
                                myfile2.write("REGEX MATCHED: " + value + " in "+ s +"\n\n")
                                myfile2.close()
                                print("\n")
                            '''





    except Exception as e:
        print(colored("[-] error occurred udentified: %s" % e, 'red'))
        print("Exception url: "+ url)
        #if("items" in json):
        #print("number of items in json: "+ str(len(json["items"])))

        #print("url_results_dict[url]: " + str(url_results_dict[url]))
        #print("query: " + str(query) + " with length: " + str(len(query)))
        #print("number of the query: " + str(x))
        #print("s: " + s)
        #print("z: " + z)
        #print("error at regex: " + str(n))
        print("\n")
        return 0

# SLEEP FUNCTION PROCESSES
def sleep(num):
    #time.sleep(60)
    #event.wait(timeout=60)           #the processes will be unpaused when ent.set is called in the main process
    #print(multiprocessing.current_process() + "has woken up\n")
    for remaining in range(60, 0, -1):
        sys.stdout.write("\r")
        sys.stdout.write("{:2d} seconds remaining.".format(remaining))
        sys.stdout.flush()
        time.sleep(1)

def my_setup(event_):
    global event
    event = event_



# SLEEP FUNCTION PROCESSES
def active(num):
    multiprocessing.dummy.Event.set()



# URL ENCODING FUNCTION
def __urlencode(str):
    str = str.replace(':', '%3A');
    str = str.replace('"', '%22');
    str = str.replace(' ', '+');
    return str


# DECLARE DICTIONARIES
url_dict = {}
results_dict = {}
url_results_dict = {}
global stats_dict
stats_dict = {
    'l_tokens': len(tokens_list),
    'n_current': 0,
    'n_total_urls': 0
}

# CREATE QUERIES
for query in queries_list:
    results_dict[query] = []
    for dork in dorks_list:
        if ":" in query:
            dork = "{}".format(query) + " " + dork
        else:
            dork = '"{}"'.format(query) + " " + dork
        url = 'https://api.github.com/search/code?q=' + __urlencode(dork)
        results_dict[query].append(url)
        url_dict[url] = 0

# CREATE ORGS
for organization in organizations_list:
    results_dict[organization] = []
    for dork in dorks_list:
        dork = 'org:' + organization + ' ' + dork
        url = 'https://api.github.com/search/code?q=' + __urlencode(dork)
        results_dict[organization].append(url)
        url_dict[url] = 0

for user in users_list:
    results_dict[user] = []
    if args.dorks:
        if args.keyword:
            for dork in dorks_list:
                for keyword in keywords_list:
                    keyword_dork = 'user:' + user + ' ' + keyword + ' ' + dork
                    url = 'https://api.github.com/search/code?q=' + __urlencode(keyword_dork)
                    results_dict[user].append(url)
                    url_dict[url] = 0

    if not args.keyword:
        for dork in dorks_list:
            dork = 'user:' + user + ' ' + dork
            url = 'https://api.github.com/search/code?q=' + __urlencode(dork)
            results_dict[user].append(url)
            url_dict[url] = 0

    if args.keyword and not args.dorks:
        for keyword in keywords_list:
            keyword = 'user:' + user + ' ' + keyword
            url = 'https://api.github.com/search/code?q=' + __urlencode(keyword)
            results_dict[user].append(url)
            url_dict[url] = 0



# STATS
stats_dict['n_total_urls'] = len(url_dict)

sys.stdout.write(colored('[#] %d organizations found.\n' % len(organizations_list), 'green'))
sys.stdout.write(colored('[#] %d users found.\n' % len(users_list), 'green'))
sys.stdout.write(colored('[#] %d dorks found.\n' % len(dorks_list), 'green'))
sys.stdout.write(colored('[#] %d keywords found.\n' % len(keywords_list), 'green'))
sys.stdout.write(colored('[#] %d queries ran.\n' % len(queries_list), 'green'))
sys.stdout.write(colored('[#] %d urls generated.\n' % len(url_dict), 'green'))
sys.stdout.write(colored('[#] %d tokens being used.\n' % len(tokens_list), 'green'))
sys.stdout.write(colored('[#] running %d threads.\n' % threads, 'green'))
print("")
# SLEEP
time.sleep(1)

# POOL FUNCTION TO RUN API SEARCH

event= multiprocessing.Event()
pool = Pool(threads, my_setup, (event,))
p= pool.map(api_search, url_dict)
pool.close()
pool.join()




new_url_list = []
result_number_list = []
dork_name_list = []
keyword_name_list = []
user_list = []



# RESULTS LOGIC FOR QUERIES
for query in queries_list:

    for url in results_dict[query]:

        if url in url_results_dict:
            new_url = url.replace('https://api.github.com/search/code',
                                  'https://github.com/search') + '&s=indexed&type=Code&o=desc'
            dork_name = dorks_list[count]
            dork_info = 'DORK = ' + dork_name + ' | '
            result_info = dork_info + new_url
            count = count + 1

            if url_results_dict[url] == 0:
                result_number = url_results_dict[url]

                new_url_list.append(new_url)
                result_number_list.append(result_number)
                dork_name_list.append(dork_name)

            else:
                result_number = url_results_dict[url]

                new_url_list.append(new_url)
                result_number_list.append(result_number)
                dork_name_list.append(dork_name)

        else:
            count = count + 1


# ADD KEYWORD TO OUTPUT TO BOTH DORKS AND ARGS
for user in users_list:



    if args.keyword and not args.dorks:
        for url in results_dict[user]:
            if url in url_results_dict:
                new_url = url.replace('https://api.github.com/search/code',
                                      'https://github.com/search') + '&s=indexed&type=Code&o=desc'
                keyword_name = keywords_list[keyword_count]
                keyword_info = 'KEYWORD = ' + keyword_name + ' | '
                result_info = keyword_info + new_url
                if len(keywords_list) - 1 != keyword_count:
                    keyword_count = keyword_count + 1
                else:
                    keyword_count = 0

                if url_results_dict[url] == 0:
                    result_number = url_results_dict[url]

                    new_url_list.append(new_url)
                    result_number_list.append(result_number)
                    keyword_name_list.append(keyword_name)
                    user_list.append(user)

                else:
                    result_number = url_results_dict[url]

                    new_url_list.append(new_url)
                    result_number_list.append(result_number)
                    keyword_name_list.append(keyword_name)
                    user_list.append(user)

            else:

                keyword_name = keywords_list[keyword_count]

                if len(keywords_list) - 1 != keyword_count:
                    keyword_count = keyword_count + 1
                else:
                    keyword_count = 0
                # Potentially code in removal from list to prevent query offset



    elif args.dorks:
        count = 0
        for url in results_dict[user]:
            if url in url_results_dict:
                new_url = url.replace('https://api.github.com/search/code',
                                      'https://github.com/search') + '&s=indexed&type=Code&o=desc'
                dork_name = dorks_list[count]

                if args.keyword:
                    keyword_name = keywords_list[keyword_count]
                    dork_info = 'DORK = ' + dork_name + ' | KEYWORD = ' + keyword_name + ' | '
                    result_info = dork_info + new_url
                    if len(keywords_list) - 1 != keyword_count:
                        keyword_count = keyword_count + 1
                    else:
                        keyword_count = 0
                        count = count + 1

                elif not args.keyword:
                    count = count + 1
                    dork_info = 'DORK = ' + dork_name + ' | '
                    result_info = dork_info + new_url

                if len(dorks_list) == count:
                    count = 0

                if url_results_dict[url] == 0:
                    result_number = url_results_dict[url]

                    new_url_list.append(new_url)
                    result_number_list.append(result_number)
                    dork_name_list.append(dork_name)
                    if args.keyword:
                        keyword_name_list.append(keyword_name)
                    user_list.append(user)

                else:
                    result_number = url_results_dict[url]

                    new_url_list.append(new_url)
                    result_number_list.append(result_number)
                    dork_name_list.append(dork_name)
                    if args.keyword:
                        keyword_name_list.append(keyword_name)
                    user_list.append(user)

            else:

                if args.keyword:
                    if len(keywords_list) - 1 != keyword_count:
                        keyword_count = keyword_count + 1
                count = count + 1
                if len(dorks_list) == count:
                    count = 0


# RESULTS LOGIC FOR ORGANIZATIONS
for organization in organizations_list:
    count=0
    for url in results_dict[organization]:

        if url in url_results_dict:
            new_url = url.replace('https://api.github.com/search/code',
                                  'https://github.com/search') + '&s=indexed&type=Code&o=desc'
            dork_name = dorks_list[count]
            dork_info = ' DORK = ' + dork_name + ' | '
            result_info = dork_info + new_url
            count = count + 1

            if url_results_dict[url] == 0:
                result_number = url_results_dict[url]

                new_url_list.append(new_url)
                result_number_list.append(result_number)
                dork_name_list.append(dork_name)

            else:
                result_number = url_results_dict[url]

                new_url_list.append(new_url)
                result_number_list.append(result_number)
                dork_name_list.append(dork_name)

        else:

            count = count + 1


# CSV OUTPUT TO FILE
if args.output:
    # FILE NAME USER INPUT
    file_name = args.output

    # DEFINE ROWS FOR KEYWORDS AND WITHOUT
    query_with_dorks_rows = zip(dork_name_list, new_url_list, result_number_list)
    user_with_keyword_only_rows = zip(user_list, keyword_name_list, new_url_list, result_number_list)
    user_with_keyword_and_dorks_rows = zip(user_list, dork_name_list, keyword_name_list, new_url_list,
                                           result_number_list)
    user_with_dorks_only_rows = zip(user_list, dork_name_list, new_url_list, result_number_list)

    # DEFINE FIELDS FOR KEYWORDS AND WITHOUT
    query_with_dorks_fields = ['DORK', 'URL', 'NUMBER OF RESULTS']
    user_with_keyword_only_fields = ['USER', 'KEYWORD', 'URL', 'NUMBER OF RESULTS']
    user_with_keyword_and_dorks_fields = ['USER', 'DORK', 'KEYWORD', 'URL', 'NUMBER OF RESULTS']
    user_with_dorks_only_fields = ['USER', 'DORK', 'URL', 'NUMBER OF RESULTS']

    # OUTPUT FOR ROWS WITH KEYWORDS AND DORKS
    with open(file_name + '_gh_dorks' + '.csv', "w") as csvfile:
        wr = csv.writer(csvfile)
        if args.query:
            wr.writerow(query_with_dorks_fields)
            for row in query_with_dorks_rows:
                wr.writerow(row)
        elif args.users or args.userfile:
            if args.keyword and args.dorks:
                wr.writerow(user_with_keyword_and_dorks_fields)
                for row in user_with_keyword_and_dorks_rows:
                    wr.writerow(row)
            elif args.keyword and not args.dorks:
                wr.writerow(user_with_keyword_only_fields)
                for row in user_with_keyword_only_rows:
                    wr.writerow(row)
            elif args.dorks and not args.keyword:
                wr.writerow(user_with_dorks_only_fields)
                for row in user_with_dorks_only_rows:
                    wr.writerow(row)

    csvfile.close()

    sys.stdout.write(
        colored("Results have been outputted into the current working directory as " + file_name + "_gh_dorks",
                'green'))
