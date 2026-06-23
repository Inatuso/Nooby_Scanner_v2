"""The HTTP web-service probes (one class per embedded device family)."""

from .ilo import ILOService
from .infoprint import InfoPrintService
from .xport import XPortService
from .sato import SATOService
from .zebra import ZebraService
from .thousandeyes import ThousandEyesService
from .cisco_voip import CiscoVoIPService
from .patlite import PatliteService
from .crestron import CrestronService
from .schneider import SchneiderService

WEB_SERVICES = [
    ILOService,
    InfoPrintService,
    XPortService,
    SATOService,
    ZebraService,
    ThousandEyesService,
    CiscoVoIPService,
    PatliteService,
    CrestronService,
    SchneiderService,
]
