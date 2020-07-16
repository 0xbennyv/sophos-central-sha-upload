# SOPHOS Central Block SHA
This tool has been designed to block SHA256 in Sohpos Central via the API. This tool can either use a CSV using the --file option or you can directly use --sha and --comment.

There's also a switch for --virustotal, this reaches out to virus total to validate the SHA against detection first. Why block something already blocked? This uses the VT Free API so make an account and get an API Key.

example:

## With VirusTotal Validation
app.py --sha a718f907745f38bbd7ac123ea148a47ed5b15fab99d409a0d6b22707cb7beaea --comment "0xBennyV Binary" --virustotal

## Without VirusTotal Validation
app.py --sha a718f907745f38bbd7ac123ea148a47ed5b15fab99d409a0d6b22707cb7beaea --comment 0xBennyV

## CSV With VirusTotal Validation
app.py --file test.csv --virustotal --output

## CSV Without VirusTotal Validation
app.py --file test.csv --output
