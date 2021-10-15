import re

test = "\n apiKey = '';\nildEnv = window.gv_prereg_env\n\t? window.gv_prereg_env.environment\n\t: process.env.REACT_APP_ENV;\nconsole.log('Build environment: ', buildEnv);\nswitch (buildEnv) "

testre = r"[:|=|\'|\"|\s*|`|´| |,|?=|\]|\|//|/\*}](apikey\s*=)[:|=|\'|\"|\s*|`|´| |,|?=|\]|\}|&|//|\*/]"
myre = re.compile(testre, re.VERBOSE | re.IGNORECASE)

match_vals = myre.findall(test)

for ref in match_vals:
    print(ref)