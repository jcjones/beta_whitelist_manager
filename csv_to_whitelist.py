#!/usr/bin/python
"""
Convert a CSV file into our Beta Whitelist format
"""

try:
  import tldextract
except:
  print("You need to 'pip install tldextract'")
  sys.exit(1)

import csv, sys, os, re, time, random
from jinja2 import Template

import malicious_url_check
import argparse
import smtplib

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# The heading values in the header row for the columns
COL_DOMAIN = "What domain(s) would you like to get a certificate for?"
COL_EMAIL = "What email address can we contact you at when we're ready for you?"

TEMPLATE_DIR = "{0}/templates".format(os.path.dirname(os.path.abspath(__file__)))
DOMAIN_PATTERN = re.compile("^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,18}$")

class DomainEntry(object):
  def __init__(self, domain="", email=""):
    self.domain = domain
    self.email = email
    self.problems = None

  def __repr__(self):
    msg = "domain={0} email={1}".format(self.domain, self.email)

    if self.problems:
      msg = "{0} problems={1}".format(msg, self.problems)

    return msg

class DummyFile(object):
    def write(self, x): pass

class DomainTester(object):
  def __init__(self):
    self.useGoogle = True
    self.registeredDomains = {}
    self.domainList = {}
    self.emailList = {}
    self.invalidList = []
    self.malList = []

  def setUseGoogle(self, value):
    self.useGoogle = value

  def checkAndAdd(self, domainEntry):
    extracted = tldextract.extract(domainEntry.domain)

    problems=[]
    if self.useGoogle:
      problems = malicious_url_check.malCheck(extracted, writer=DummyFile())
      if problems:
        domainEntry.problems = problems
        self.malList.append(domainEntry)

    if not problems:
      if domainEntry.email not in self.emailList:
        self.emailList[domainEntry.email] = set()

      self.emailList[domainEntry.email].add(domainEntry.domain)
      self.domainList[domainEntry.domain] = domainEntry.email
      self.registeredDomains[extracted.registered_domain] = domainEntry.email

      print(domainEntry)

    return problems

  def processEntry(self, domains=[], email=""):
    for domain in re.split('[,; ]', domains):
      domain = domain.lower()
      domain = re.sub("[ ]*(http|https)://", "", domain)
      domain = re.sub("\*\.", "", domain)
      domain = domain.strip()

      if len(domain) < 2:
        continue

      domainEntry = DomainEntry(domain=domain, email=email)

      if not DOMAIN_PATTERN.match(domain):
        print ("Invalid: {0}".format(domainEntry))
        self.invalidList.append(domainEntry)
        continue

      try:
        problems = self.checkAndAdd(domainEntry)
        if problems:
          continue

        if not "www." in domain:
          domainWww = "www.{0}".format(domain)
          domainEntryWww = DomainEntry(domain=domainWww, email=email)
          self.checkAndAdd(domainEntryWww)
        else:
          domainNaked = domain.lstrip("www.")
          domainEntryNaked = DomainEntry(domain=domainNaked, email=email)
          self.checkAndAdd(domainEntryNaked)

      except:
        print("Caught exception at {0}".format(domainEntry))

  def listByDomain(self):
    return self.domainList

  def listByEmail(self):
    return self.emailList

  def listInvalid(self):
    return self.invalidList

  def listProblem(self):
    return self.malList

  def listByRegisteredDomain(self):
    return self.registeredDomains

def make_messageId():
  timeval = time.time()
  utcdate = time.strftime('%Y%m%d%H%M%S', time.gmtime(timeval))
  pid = os.getpid()
  randint = random.randrange(100000)
  idstring = "betaprogram@letsencrypt.org"
  return "<{0}.{1}.{2}.{3}>".format(utcdate, pid, randint, idstring)

def sendEmail(contents):
  from jinja2 import Environment, FileSystemLoader

  env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
  txtTemplate = env.get_template('beta.txt.j2')
  htmlTemplate = env.get_template('beta.html.j2')

  addrFrom = "Let's Encrypt Beta <betaprogram@letsencrypt.org>"
  addrTo = contents['email']

  # mailServer = "10.0.12.40"
  mailServer = "10.0.32.40"

  msgRoot = MIMEMultipart()
  msgRoot['Subject'] = "Let's Encrypt Closed Beta Invite"
  msgRoot['From'] = addrFrom
  msgRoot['To'] = addrTo
  msgRoot['Message-Id'] = make_messageId()
  msgRoot.preamble = 'This is a multi-part message in MIME format.'

  msgAlternative = MIMEMultipart('alternative')
  msgRoot.attach(msgAlternative)

  msgText = MIMEText(txtTemplate.render(contents))
  msgAlternative.attach(msgText)

  msgText = MIMEText(htmlTemplate.render(contents), 'html')
  msgAlternative.attach(msgText)

  s = smtplib.SMTP(mailServer)
  s.sendmail(addrFrom, [addrTo], msgRoot.as_string())
  s.quit()
  print("Email sent to {0}".format(addrTo))

def processCSV(args):
  tester = DomainTester()
  tester.setUseGoogle(not args.noGoogle)

  lineCount = 0
  lineLimit = args.limit
  lineOffset = args.offset
  emailSent = 0

  with open(args.csv, "r") as csvFile:
    reader = csv.DictReader(csvFile)
    for row in reader:
      if lineOffset and lineOffset > 0:
        lineOffset -= 1
        continue

      tester.processEntry(domains=row[COL_DOMAIN], email=row[COL_EMAIL])

      lineCount += 1

      if lineLimit:
        lineLimit -= 1
        if lineLimit < 1:
          break

    if args.out:
      with open(args.out, "w") as outFile:
        for domain, email in tester.listByDomain().iteritems():
          outFile.write('- "{0}" # {1}\n'.format(domain.strip(), email))

    if args.email:

      for email, domains in tester.listByEmail().iteritems():

        # Email override
        if args.emailOverride:
          email = "jcjones@letsencrypt.org"

        sendEmail({
          "domains": domains,
          "email": email
        })

        emailSent += 1

    if args.verbosity > 1:
      for domain in tester.listInvalid():
        print("Invalid: {0}".format(domain))

    if args.verbosity > 0:
      for domain in tester.listProblem():
        print("Problem: {0}".format(domain))

    print("Processed {entryCount} rows from limit {limit} offset {offset}. "
      "This was {domainCount} domains, {registeredCount} registered domains, and {emailCount} email addresses. "
      "{invalidCount} were invalid, {probCount} were flagged malicious. "
      "Sent {emailSent} emails.".format(
        entryCount=lineCount, limit=args.limit,
        offset=args.offset, emailSent=emailSent,
        domainCount=len(tester.listByDomain()),
        registeredCount=len(tester.listByRegisteredDomain()),
        emailCount=len(tester.listByEmail()),
        invalidCount=len(tester.listInvalid()),
        probCount=len(tester.listProblem())
      ))


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("-v", dest='verbosity', help="Increase verbosity", action='count')
  parser.add_argument("--email", help="Enable email", action='store_true')
  parser.add_argument("--emailOverride", help="Override", action='store_true')
  parser.add_argument("--noGoogle", help="Disable Google Safebrowsing", action='store_true')

  parser.add_argument("--update", help="Update Safebrowsing", action='store_true')
  parser.add_argument("--csv", help="CSV File")

  parser.add_argument("--out", help="YAML Fragment File")
  parser.add_argument("--offset", help="Skip rows in the CSV", type=int)
  parser.add_argument("--limit", help="Number of rows to process",  type=int)
  args = parser.parse_args()

  if args.csv:
    malicious_url_check.loadLists()
    processCSV(args)

  if args.update:
    print ("Updating Safebrowsing...")
    malicious_url_check.updateSafebrowsing()

if __name__ == "__main__":
 main()