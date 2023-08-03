from plugin.detectors.emergency_stop_pattern import EmergencyStopPattern
from plugin.detectors.oracle_pattern import OraclePattern
from plugin.detectors.guard_check_pattern import GuardCheckPattern
from plugin.detectors.facade_pattern import FacadePattern
from plugin.detectors.contract_info import ContractInfo

def make_plugin():
    plugin_detectors = [EmergencyStopPattern, OraclePattern, GuardCheckPattern, FacadePattern, ContractInfo]
    plugin_printers = []

    return plugin_detectors, plugin_printers