# Beta Whitelist Manager
Send beta test emails


### Email 1000 rows via 192.168.1.1
```
python ./csv_to_whitelist.py --csv ~/Downloads/beta-20151026.csv --offset 10000 --limit 1000 --emailServer 192.168.1.1
```

### Produce YAML for 1000 rows
```
python ./csv_to_whitelist.py --csv ~/Downloads/beta-20151026.csv --offset 10000 --limit 1000 --out /tmp/10000-11000.yaml
```

### Update SafeBrowsing
```
python ./csv_to_whitelist.py --update
```