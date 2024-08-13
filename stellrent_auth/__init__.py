import logging
from decouple import config
import sys

global log
LOG_LEVEL = config('STELLRNT_AUTH_LOG_LEVEL', default='INFO')
log = logging.getLogger(__name__.upper())
log.setLevel(LOG_LEVEL)

log.info("Initializing module")