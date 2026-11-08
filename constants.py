from config import (
    DEFAULT_USER_AGENT,
    GENERAL_PARAMS,
    REDIRECT_PARAMS,
    EXCLUDED_VARS,
    EXCLUDED_VARS_REGEX,
    XSS_HEADERS,
)

VERSION = "2.1.1"

BANNER = rf"""
 ___  ___   ________  ________  _______   
|"  \/"  | /"       )/"       )/"      \  
 \   \  / (:   \___/(:   \___/|:        | 
  \\  \/   \___  \   \___  \  |_____/   ) 
  /\.  \    __/  \\   __/  \\  //      /  
 /  \   \  /" \   :) /" \   :)|:  __   \  
|___/\___|(_______/ (_______/ |__|  \___) 
{f"v{VERSION}":>41}
"""

APP = "XSSRush"
DESCRIPTION = "Automated Multi-Vector XSS Scanner"
AUTHOR = "N45HT"
HOMEPAGE = "https://n45ht.or.id"
EMAIL = "security@n45ht.or.id"
GITHUB = "https://github.com/N45HT/XSSRush"

__all__ = [
    "BANNER",
    "APP",
    "DESCRIPTION",
    "AUTHOR",
    "HOMEPAGE",
    "EMAIL",
    "GITHUB",
    "VERSION",
    "DEFAULT_USER_AGENT",
    "GENERAL_PARAMS",
    "REDIRECT_PARAMS",
    "EXCLUDED_VARS",
    "EXCLUDED_VARS_REGEX",
    "XSS_HEADERS",
]
