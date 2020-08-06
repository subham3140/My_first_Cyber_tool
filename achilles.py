#!/usr/bin/env python

# Here to pass arguments directly through your command terminal
# we use this import 
# import sys

# # Here this is the basic way of doing Arguments parsing from the command 
# # line in python

# # print("The first arguments was:" + sys.argv[1])
# # print("The second arguments was:" + sys.argv[2])

# print(sys.argv)

# //////////////////////////////////////////////////////


import argparse

# Here we have this validators for validating the url
import validators

import requests

# Here we are importing a very important package provided by python by which we 
# parse the document we got through ./achilles.py http:/localhost:8000/ url and 
# that package is urlparse from urllib.parse
from urllib.parse  import urlparse
# And also a BeautifulSoup from bs4 (BeautifulSoup is an open source library for parse document)
from bs4 import BeautifulSoup
from bs4 import Comment
import yaml

# Here this arguments is trigger by -h which describe whaterver we want
parser = argparse.ArgumentParser(description="The Achilles HTML Vulnerablity Analyze Version 1.0")
# Here this arguments by triggring -v or --version is for getting the version of our app as we describe action 
parser.add_argument('-v','--version',action='version',version='%(prog)s 1.0')
# In the same way we can add arguments for url like this:
parser.add_argument('url',type=str,help="The URL of the HTML to Analyze")
# Now here we are going to add new arguments for configuration files
parser.add_argument('--config',help='Path to congifguration file')
# Now we want to add one more argumentsto allow to open the output file 
parser.add_argument('-o','--output',help='Report file output path')

args = parser.parse_args()

# We can use default config if we have't any config file
config = {'forms':True,'comments':True,'password_inputs':True}

# print(args.config)
if (args.config):
	print('Using config file: '+args.config)
	# here we are talking about some configuration with proper
	# format and consistent format for our configurations setting
    # so that we can open that file and apply 'r',so there is a 
    # file format that frequently use in python is called 
    # yaml(Yet another markup language),so we use the yaml file 
    # as open this file and load the yaml file and convert it into
    # a python object so that we can use it
	config_file = open(args.config,'r')
	# Rightnow iur config file is now a string 
	# config = yaml.load(config_file) 
	        # or
	# If we use this yaml.load() method wither Loader arguments
	# then we get a warning ,so to disable warning we need to add
	# Loader as Loader=yaml.FullLoader to remove warning
	config_from_file = yaml.load(config_file,Loader=yaml.FullLoader)
	# each elements in config file are in dictionary 
	# print(config['forms'])
	# print(config['comments'])
	# print(config['password_inputs'])
	if (config_from_file):
		# Here below this it means take config as **config(this is existing config
		# with ** means expand this dictionary) otherwise take config 
		# as **config_from_file(which is the value to be updated and **means the same i.e.
		# expand the dictionary )
		config = {**config , **config_from_file}
	# Now by this config we can handel the forms,comments,password
	# as we describe each one as a boolean in config.yaml file,
	# so just see how we use that boolean
	# print(config)
# print(args.url)
url = args.url


report = ''

# # print(validators.url(url))
if (validators.url(url)):
	result_html = requests.get(url).text
	# Here we are taking a variable parsed_html in which we assign the results of calling
# 	# the BeautifulSoup constructer on result_html using html_parser as default parser
# 	# Remember that this parsed_html variable looks like a string but indeed it is 
# 	# collection of objects like we see here 'form' ,'title' ,'h1' ,'a' and so on

# 	parsed_html = BeautifulSoup(result_html,'html.parser')
	parsed_html = BeautifulSoup(result_html,'html.parser')

	# print(parsed_html.prettify())
# 	# We can do many things which is very intresting because that parsed_html now has verious variety of methods
# 	# print(parsed_html.find_all('title'))
# 	       # OR
# 	# print(parsed_html.title)
# 	# print(parsed_html.find_all('form'))
# 	# print(parsed_html.find_all('h1'))
# 	# print(parsed_html.find_all('a'))

# 	# This variable is for checking any http or url present or not
	forms = parsed_html.find_all('form')

# 	# We also want to check that if by a chance anyone left a comment with some sensitive keys or secrete
#   # key that we can track it by using Comment from BeautifulSoup(bs4)
	
#   # This variable is for checking any comments with sensitive information is by accidently lefted or not
	comments = parsed_html.find_all(string=lambda text:isinstance(text,Comment))

# 	# This variable is to check for a password form by a html form as a plan text field so that when 
# 	# password is submited then it is as a plan text

	password_inputs = parsed_html.find_all('input', {'name':'password'})

#   # For form checking
	if (config['forms']):
		for form in forms:
			if((form.get('action').find('https') < 0) and (urlparse(url).scheme != 'https')):
				# form_is_secure = False
				# print(form_is_secure) 
				# report += 'Form Issue:Insecure form found in documents\n'
				               # OR
				report += 'Form Issue:Insecure form action ' + form.get('action') + ' found in document.\n'

    # For comment checking
	if (config['comments']):
		for comment in comments:
			if(comment.find('key: ') > -1):
				report += 'Comment Issue: Key in the HTML comments,Please remove.\n'

   
    # For password checking
	if (config['password_inputs']):
		for password in password_inputs:
			if(password.get('type') != 'password'):
				report += 'Input Issue:PlanText password input found.Please change the input type=password otherwise your password will be catch easily as a simple text.\n'


else:
	print("Invalid URL Please include full URL including scheme.")


if(report == ''):
	# print('Nice job! your HTML document is secure')
    report +='Nice job! your HTML document is secure\n'
else:
	# print('Vulnerability Report is as follows:\n')
	header ='Vulnerability Report is as follows:\n'
	# print('===================================\n')
	header +='===================================\n\n'

	report = header + report

print(report)
 

if (args.output):
	# print(args.output)
	# f = open(args.output,'w')
	# f.write(report)
	# f.close
	  # or
	with open(args.output,'w') as f:
		f.write(report)
	print('Report saved to: '+args.output)
 
























