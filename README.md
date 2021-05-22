# FoxDorker
A Python program to scrape secrets from GitHub through usage of regular expressions

FoxDorker is a fork of the more famous GitDorker that instead of using simple Dorks makes use of more complex regular expressions that I've built to provide a more in depth overview of sensitive information stored on github given a search query.

# Requirements
** Python3

** GitHub Personal Access Token

** Install requirements inside of the requirements.txt file of this repo (pip3 install -r requirements.txt)

Please follow the guide below if you are unsure of how to create a personal access token: https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token

# Recommendations
It is recommended to provide GitDorker with at least two GitHub personal access tokens so that it may alternate between the two during the dorking process and reduce the likelihood of being rate limited. Using multiple tokens from separate GitHub accounts will provide the best results.

# Options
-k KEYWORD, --keyword KEYWORD --> search on a keyword instead of a list of dorks
-q QUERY, --query QUERY --> query (required or -q)
-u USERS, --users USERS --> users to perform dork or keyword search on (comma separated).
-uf USERFILE, --userfile USERFILE --> file containing new line separated users
-org ORGANIZATION, --organization ORGANIZATION --> organization's GitHub name (required or -org if query not specified)
-t TOKEN, --token TOKEN --> your github token (required if token file not specififed)
-tf TOKENFILE, --tokenfile TOKENFILE --> file containing new line separated github tokens
-e THREADS, --threads THREADS --> maximum n threads, default 1
-o OUTPUT, --output OUTPUT --> output to file name (required or -o)

# Example Usage
python3 FoxDorker.py -tf tokens.txt -d ./Dorks/wordlist.txt -org singleDomain.txt -e 9

