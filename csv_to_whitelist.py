#!/usr/bin/python
"""
Convert a CSV file into our Beta Whitelist format
"""

try:
  import tldextract
except:
  print("You need to 'pip install -r requirements.txt'")
  sys.exit(1)

import csv, sys, os, re, time, random, shelve
from jinja2 import Template

import malicious_url_check
import argparse
import smtplib

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# The heading values in the header row for the columns
COL_DOMAIN = "What domain(s) would you like to get a certificate for?"
COL_EMAIL = "What email address can we contact you at when we're ready for you?"

TEMPLATE_DIR = "{0}/templates".format(os.path.dirname(os.path.abspath(__file__)))
DOMAIN_PATTERN = re.compile("^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,18}$")
PUNYCODE_PATTERN = re.compile("xn--")

class DomainEntry(object):
  def __init__(self, extracted, domain="", email=""):
    self.extracted = extracted
    self.domain = domain
    self.email = email
    self.problems = []
    self.addedDate = None
    self.safebrowsingDate = None
    self.notificationDate = None

  def __repr__(self):
    msg = "domain={0} email={1}".format(self.domain, self.email)

    if self.problems:
      msg = "{0} problems={1}".format(msg, self.problems)

    if self.safebrowsingDate:
      msg = "{0} S".format(msg)

    if self.addedDate:
      msg = "{0} A".format(msg)

    if self.notificationDate:
      msg = "{0} N".format(msg)

    return msg

  def isInvalid(self):
    if not DOMAIN_PATTERN.match(self.domain):
      return True
    if PUNYCODE_PATTERN.match(self.domain):
      return True
    return False

  def hasProblems(self):
    return len(self.problems) > 0

  def check(self, withMalCheck=True):
    self.problems=[]
    if not DOMAIN_PATTERN.match(self.domain):
      self.problems.append("Invalid format")
      return
    if PUNYCODE_PATTERN.match(self.domain):
      self.problems.append("Punycode not permitted")
      return
    if not self.extracted:
      self.problems.append("Unparseable domain name")
      return

    if withMalCheck and not self.safebrowsingDate:
      malProblems = malicious_url_check.malCheck(self.extracted,
          writer=DummyFile())
      self.problems.extend(malProblems)
      self.safebrowsingDate = datetime.now()

  def getRegisteredDomain(self):
    return self.extracted.registered_domain


class DummyFile(object):
    def write(self, x): pass

class DomainTester(object):
  def __init__(self):
    self.useGoogle = True
    self.registeredDomains = {}
    self.emailList = {}
    self.invalidList = []
    self.malList = []
    self.shelf = None

  def setUseGoogle(self, value):
    self.useGoogle = value

  def associateDomainWithEmail(self, domainEntry):
    if domainEntry.email not in self.emailList:
      self.emailList[domainEntry.email] = set()

    self.emailList[domainEntry.email].add(domainEntry.domain)

  def loadShelf(self, shelf):
    self.shelf = shelf

    for domain, domainObj in shelf.iteritems():
      assert type(domainObj) is DomainEntry
      self.checkAndTally(domainObj)

  def getOrCreateDomainEntry(self, domain=None, email=None):
    if domain not in self.shelf:
      try:
        extracted = tldextract.extract(domain)
      except ValueError, ve:
        print("Couldn't decode domain {0}: {1}".format(domain, ve))

      self.shelf[domain] = DomainEntry(extracted, domain=domain, email=email)

    return self.shelf[domain]

  def getDomain(self, domainName):
    obj = self.shelf[domainName]
    assert type(obj) is DomainEntry
    return obj

  def checkAndTally(self, domainEntry):
    domainEntry.check(withMalCheck=self.useGoogle)

    if domainEntry.hasProblems():
      if domainEntry.isInvalid():
        self.invalidList.append(domainEntry)
      else:
        self.malList.append(domainEntry)
    else:
      self.associateDomainWithEmail(domainEntry)
      self.registeredDomains[domainEntry.getRegisteredDomain()] = domainEntry.email

  def getWwwComplementName(self, domainObj):
      assert type(domainObj) is DomainEntry
      if domainObj.extracted.subdomain == "www":
        return domainObj.extracted.registered_domain
      if len(domainObj.extracted.subdomain) < 1:
        return "www.{0}".format(domainObj.extracted.registered_domain)
      return None

  def processEntry(self, domains=[], email=""):
    for domain in re.split('[,; ]', domains):
      domain = domain.lower()
      domain = re.sub("[ ]*(http|https)://", "", domain)
      domain = re.sub("\*\.", "", domain)
      domain = domain.strip()

      if len(domain) < 2:
        continue

      domainEntry = self.getOrCreateDomainEntry(domain=domain, email=email)
      domainEntry.check()

      if domainEntry.check():
        self.invalidList.append(domainEntry)

      try:
        self.checkAndTally(domainEntry)
        if domainEntry.problems:
          continue

        # If it has a WWW, get the not-WWW form. Or add a WWW.
        compDomain = self.getWwwComplementName(domainEntry)
        if compDomain:
          compEntry = self.getOrCreateDomainEntry(domain=compDomain, email=email)
          self.checkAndTally(compEntry)

      except (KeyboardInterrupt, SystemExit):
        raise
      except Exception, err:
        print("Caught exception at {0}: {1}".format(domainEntry, err))

  def listObjectsByDomain(self):
    return self.shelf

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

def sendEmail(contents, mailServer=None):
  from jinja2 import Environment, FileSystemLoader

  env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
  txtTemplate = env.get_template('beta.txt.j2')
  htmlTemplate = env.get_template('beta.html.j2')

  addrFrom = "Let's Encrypt Beta <betaprogram@letsencrypt.org>"
  addrTo = contents['email']

  msgRoot = MIMEMultipart()
  msgRoot['Subject'] = "Let's Encrypt Closed Beta Invite"
  msgRoot['From'] = addrFrom
  msgRoot['To'] = addrTo
  msgRoot['Message-Id'] = make_messageId()
  msgRoot['Date'] = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S +0000")
  msgRoot.preamble = 'This is a multi-part message in MIME format.'

  msgAlternative = MIMEMultipart('alternative')
  msgRoot.attach(msgAlternative)

  msgText = MIMEText(txtTemplate.render(contents))
  msgAlternative.attach(msgText)

  msgText = MIMEText(htmlTemplate.render(contents), 'html')
  msgAlternative.attach(msgText)

  if not mailServer:
    print(msgRoot)
    return

  mailServer.sendmail(addrFrom, [addrTo], msgRoot.as_string())
  print("Email sent to {0}".format(addrTo))

def processCSV(args, shelf=None):
  tester = DomainTester()
  tester.setUseGoogle(not args.noGoogle)
  tester.loadShelf(shelf)

  lineCount = 0
  lineLimit = args.limit
  lineOffset = args.offset
  emailSent = 0

  if args.csv:
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
  # Done with reading file, so tester knows all domains

  # Produce output file
  if args.out:
    with open(args.out, "w") as outFile:
      outFile.write("beta-whitelist: # Produced {0}\n".format(datetime.now().isoformat()))
      domainsToWrite = tester.listObjectsByDomain()
      for domain in sorted(domainsToWrite):
        obj = tester.getDomain(domain)
        if obj.hasProblems():
          continue
        if not obj.addedDate:
          obj.addedDate = datetime.now()
        outFile.write('  - "{0}" # {1} {2}\n'.format(domain.strip(), obj.email, obj.addedDate))

  # Send emails
  if args.emailServer:
    if args.emailServer.lower() == "none":
      print("Not actually sending.")
      mailServer = None
    else:
      print("Sending email via {0}".format(args.emailServer))
      mailServer = smtplib.SMTP(args.emailServer)

    emailsToSend = tester.listByEmail()
    for email in tester.listByEmail():
      newDomains = []
      oldDomains = []

      # Limit quantity
      if args.emailBatch is not None and emailSent >= args.emailBatch:
        break

      # Determine if there are changes
      for domain in emailsToSend[email]:
        domainObj = tester.getDomain(domain)
        if domainObj.hasProblems():
          continue

        if not domainObj.notificationDate:
          newDomains.append(domainObj.domain)
        else:
          oldDomains.append(domainObj.domain)

      if args.emailOverride:
        email = args.emailOverride

      # Only send an email if we have changes
      if len(newDomains) > 0:
        sendEmail({
          "domains": newDomains + oldDomains,
          "email": email
        }, mailServer=mailServer)

        emailSent += 1

      # Only mark this domain as being notified if we are
      # actually sending them the email
      if mailServer and not args.emailOverride:
        for domain in newDomains:
          domainObj = tester.getDomain(domain)
          domainObj.notificationDate = datetime.now()

    # End of for email loop

    if mailServer:
      mailServer.quit()

  # Show results
  if args.verbosity > 2:
    for domainName, domainObj in tester.listObjectsByDomain().iteritems():
      print(domainObj)

  if args.verbosity > 1:
    for domain in tester.listInvalid():
      print("Invalid: {0}".format(domain))

  if args.verbosity > 0:
    for domain in tester.listProblem():
      print("Problem: {0}".format(domain))

  print("Processed {entryCount} rows from limit {limit} offset {offset}. "
    "This was {domainCount} domains, {registeredCount} registered domains, and {emailCount} email addresses. "
    "{invalidCount} were invalid, {probCount} were flagged malicious. "
    "Sent {emailSent} emails, limited to {emailBatch}.".format(
      entryCount=lineCount, limit=args.limit,
      offset=args.offset, emailSent=emailSent,
      emailBatch=args.emailBatch,
      domainCount=len(tester.listObjectsByDomain()),
      registeredCount=len(tester.listByRegisteredDomain()),
      emailCount=len(tester.listByEmail()),
      invalidCount=len(tester.listInvalid()),
      probCount=len(tester.listProblem())
    ))

def sortNewOldDomains(tester, domainList):
  values = { 'new': [], 'old': [] }

  for domain in domainList:
    domainObj = tester.getDomain(domain)
    if domainObj.hasProblems():
      continue

    if not domainObj.notificationDate:
      values['new'].append(domainObj.domain)
    else:
      values['old'].append(domainObj.domain)

  return values

def getStats(args, shelf=None):
  tester = DomainTester()
  tester.setUseGoogle(False)
  tester.loadShelf(shelf)

  numEmails=0
  numToDoEmails=0
  numNewUsers=0

  for emailAddress, domainList in tester.listByEmail().iteritems():
    values = sortNewOldDomains(tester, domainList)

    numEmails += 1
    if len(values['new']) > 0:
      numToDoEmails += 1
      if len(values['old']) == 0:
        numNewUsers += 1

    if args.verbosity > 0:
      print("{email} [Total Domains: {domains}] [New Domains: {newDomains}]".format(
        email=emailAddress,
        domains=len(domainList),
        newDomains=len(values['new'])
      ))

  print("There are {emailCount} email addresses, and {pending} of them are "
    "waiting on an email. Of those, {newUsers} are new users.".format(
      emailCount=numEmails,
      pending=numToDoEmails,
      newUsers=numNewUsers
    ))


def main():
  parser = argparse.ArgumentParser(description=__doc__)

  parser.add_argument("--db",  help="Database", default="whitelist.db")
  parser.add_argument("-v", dest='verbosity', help="Increase verbosity", action='count')
  parser.add_argument("--emailServer", help="Send email via server")
  parser.add_argument("--emailOverride", help="Override recipient")
  parser.add_argument("--emailBatch", help="Number of emails to send",  type=int)
  parser.add_argument("--noGoogle", help="Disable Google Safebrowsing", action='store_true')

  parser.add_argument("--update", help="Update Safebrowsing", action='store_true')
  parser.add_argument("--stats", help="Get stats", action='store_true')
  parser.add_argument("--csv", help="Import CSV File")

  parser.add_argument("--out", help="YAML Fragment File")
  parser.add_argument("--offset", help="Skip rows in the CSV", type=int)
  parser.add_argument("--limit", help="Number of rows to process",  type=int)
  args = parser.parse_args()

  if args.update:
    print ("Updating Safebrowsing...")
    malicious_url_check.updateSafebrowsing()
    return

  shelf = shelve.open(args.db, writeback=True)
  try:
    if args.stats:
      getStats(args, shelf=shelf)
      return

    malicious_url_check.loadLists()
    processCSV(args, shelf=shelf)
  finally:
    shelf.close()
    print("Done.")

if __name__ == "__main__":
 main()