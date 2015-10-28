#!/usr/bin/python
import requests, os, time, sys, zipfile
from StringIO import StringIO

try:
  from gglsbl import SafeBrowsingList
except:
  print("You need to 'pip install gglsbl'")
  sys.exit(1)

try:
  import tldextract
except:
  print("You need to 'pip install tldextract'")
  sys.exit(1)


safebrowsing_token = 'AIzaSyBKlevd7lUJpEq0XGnvaojrmS9OJqWY6YA'
isc_url = 'https://isc.sans.edu/feeds/suspiciousdomains_Low.txt'
topmillion_url = 'http://s3.amazonaws.com/alexa-static/top-1m.csv.zip'

safebrowsing_db = os.environ['HOME'] + '/Downloads/safebrowsing.db'
suspect_file = os.environ['HOME'] + '/Downloads/suspiciousdomains_Low.txt'
topthousand_file = os.environ['HOME'] + '/Downloads/alexa_1000.csv'

safebrowsing_bootstrap = not os.path.exists(safebrowsing_db) or (os.path.getsize(safebrowsing_db) < 10000)

# Be sure to occasionally run sbl.update_hash_prefix_cache()
sbl = SafeBrowsingList(safebrowsing_token, db_path=safebrowsing_db)

ISC_LIST=[]
ALEXA_LIST=[]

def loadLists(writer=sys.stdout):
  if isStale(suspect_file):
    print >> writer, "Updating ISC Suspicious Domains..."
    new_file = requests.get(isc_url)
    with open(suspect_file, 'w') as sf_buffer:
      sf_buffer.write(new_file.content)

  if safebrowsing_bootstrap:
      print("Initial download of SafeBrowsing DB... this will take a few minutes.")
      updateSafebrowsing()
  elif isStale(safebrowsing_db, maxTime=259200):
    print >> writer, "Updating Google Safebrowsing DB..."
    updateSafebrowsing()

  if isStale(topthousand_file, maxTime=2629743):
    print >> writer, "Updating Alexa Top 1000..."
    new_file = requests.get(topmillion_url)
    with zipfile.ZipFile(StringIO(new_file.content), 'r') as zipData:
      with zipData.open('top-1m.csv', 'r') as oneMil:
        with open(topthousand_file, 'w') as topThousand:
          for i in range(0,1000):
            topThousand.write(oneMil.readline())

  for sf_read in open(suspect_file):
    badDomain = tldextract.extract(sf_read)
    ISC_LIST.append(badDomain)

  for topthousand_read in open(topthousand_file):
    cleaned_line = topthousand_read.split(",")[1].strip()
    valuableDomain = tldextract.extract(cleaned_line)
    ALEXA_LIST.append(valuableDomain)


def updateSafebrowsing():
  sbl.update_hash_prefix_cache()

def isStale(filePath, maxTime=86400):
  """
  Check if file is older than maxTime and refresh if needed
  """
  return (not os.path.exists(filePath)) or (time.time() - os.path.getmtime(filePath)) > maxTime

def malCheck(check_url, writer=sys.stdout):
  problems=[]

  if not ALEXA_LIST or not ISC_LIST:
    raise Exception("You must call loadLists() first!")

  if len(check_url.suffix) < 2:
    problems.append("Invalid TLD")
    return problems

  print >> writer, "Checking maliciousness of {0}".format(check_url)

  # Check if URL is in suspicious domains list from SAN ISC
  for sf_read in open(suspect_file):
    sf = tldextract.extract(sf_read)

    if sf.registered_domain == check_url.registered_domain:
      problems.append("Matches ISC suspicious domain {0}".format(sf))

  for topthousand_read in open(topthousand_file):
    cleaned_line = topthousand_read.split(",")[1].strip()
    valuableDomain = tldextract.extract(cleaned_line)

    if valuableDomain.registered_domain == check_url.registered_domain:
      problems.append("Matches Alexa Top 1000 domain {0}".format(valuableDomain))

  # ISC Suspicious Domains
  for badDomain in ISC_LIST:
    if badDomain.registered_domain == check_url.registered_domain:
      problems.append("Matches ISC suspicious domain {0}".format(badDomain))

  # Alexa Top 1000
  for valuableDomain in ALEXA_LIST:
    if valuableDomain.registered_domain == check_url.registered_domain:
      problems.append("Matches Alexa Top 1000 domain {0}".format(valuableDomain))

  # Check against Google Safe Browsing API
  sbr = sbl.lookup_url(check_url)
  if sbr:
    problems.extend(sbr)

  return problems

if __name__ == "__main__":
  loadLists()

  for url in sys.argv[1:]:
    extracted = tldextract.extract(url)
    results = malCheck(extracted)
    for res in results:
      print("Malicious: {0}".format(results))
