from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations.contract import Contract
from slither.core.declarations.function_contract import FunctionContract
from slither.core.expressions.member_access import MemberAccess
from slither.core.expressions.call_expression import CallExpression
from plugin.detectors.utils import get_external_contracts, get_function_signiture, is_overriden

class FacadePattern(AbstractDetector):
    '''
    Documentation
    '''

    ARGUMENT = 'facade'
    HELP = 'Help printed by slither'
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = 'Wiki'

    WIKI_TITLE = 'wiki title'
    WIKI_DESCRIPTION = 'wiki desc'
    WIKI_EXPLOIT_SCENARIO = 'wiki scenario'
    WIKI_RECOMMENDATION = 'wiki rec'
    
    def check_for_chained_calls(self, function: FunctionContract):
        exContracts = get_external_contracts(function.contract)

        calls = filter(lambda ex: isinstance(ex, CallExpression) and isinstance(ex.called, MemberAccess) and any(map(lambda exContract: str(ex).startswith(exContract[1]), exContracts)), function.expressions)

        return len(list(calls)) > 1

    def _detect(self):
        info = []
        
        for contract in self.slither.contracts:
            for function in filter(lambda f: not is_overriden(f), contract.functions):
                if self.check_for_chained_calls(function):
                    if function.visibility in ('public', 'external'):
                        info.append(f'DETECTOR WARNING: Chained external calls detected in {function.visibility} function {get_function_signiture(function)}.\nConsider the use of a facade pattern to isolate external calls for better error handling and the reduction of likelyhood of catastrophic failure.\n\n')
                    else:
                        info.append(f'DETECTOR INFO: Facade pattern detected in {function.visibility} function {get_function_signiture(function)}.\n\n')

        res = self.generate_result(info)

        if info:
            return [res]
        
        return []